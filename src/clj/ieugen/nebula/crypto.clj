(ns ieugen.nebula.crypto
  (:import (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest SecureRandom Security)
           (java.util HexFormat)
           (org.bouncycastle.crypto AsymmetricCipherKeyPair)
           (org.bouncycastle.crypto.ec CustomNamedCurves)
           (org.bouncycastle.crypto.generators ECKeyPairGenerator Ed25519KeyPairGenerator)
           (org.bouncycastle.crypto.params
            ECDomainParameters
            ECKeyGenerationParameters
            ECPrivateKeyParameters
            Ed25519KeyGenerationParameters
            Ed25519PrivateKeyParameters
            Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)
           (org.bouncycastle.crypto.util SubjectPublicKeyInfoFactory)
           (org.bouncycastle.jce ECNamedCurveTable)
           (org.bouncycastle.jce.provider BouncyCastleProvider)
           (org.bouncycastle.math.ec.rfc7748 X25519)) 
  (:require [ieugen.nebula.pem :as pem]
            [failjure.core :as f]))

(Security/addProvider (BouncyCastleProvider.))

(defn security-providers
  "Get security providers registered with the JVM."
  []
  (Security/getProviders))

(def secure-random-gen (SecureRandom.))

(defn ec-named-curves-seq
  "Return a sequence of EC curves."
  []
  (enumeration-seq (ECNamedCurveTable/getNames)))

(defn curve-str-kw
  "Return a keyword from curve str or nil."
  [curve]
  (case curve
    ("25519" "X25519" "Curve25519" "CURVE25519") :Curve25519
    "P256" :P256
    nil))

^:rct/test
(comment

  (map curve-str-kw ["25519" "X25519" "Curve25519" "CURVE25519" "P256" "Invalid"])
  ;; => (:Curve25519 :Curve25519 :Curve25519 :Curve25519 :P256 nil)

  (ec-named-curves-seq))
(def my-hex-fmt ^HexFormat (HexFormat/of))

(defn bytes->hex
  [bytes]
  (.formatHex ^HexFormat my-hex-fmt bytes))

(defn hex->bytes
  [hex-str]
  (.parseHex ^HexFormat my-hex-fmt hex-str))

(defn sha256sum
  [^bytes bytes]
  (let [sha256 (MessageDigest/getInstance "SHA-256")]
    (.digest sha256 bytes)))

(defn sha256sum+hex
  [^bytes bytes]
  (bytes->hex (sha256sum bytes)))

(defn str->bytes
  ([^String str]
   (str->bytes str StandardCharsets/UTF_8))
  ([^String str ^Charset charset]
   (.getBytes str charset)))

^:rct/test
(comment

  (bytes->hex (str->bytes "nebula!"))
  ;; => "6e6562756c6121"

  (sha256sum+hex (str->bytes "nebula!"))
  ;; => "c6e2203722c7a16df027a78e6a982bc505a9c92c2ec71a5f8de2d59f877db35a"
  )

;; https://github.com/slackhq/nebula/blob/master/cert/cert.go#L29

(def cert-banners
  {:CertBanner "NEBULA CERTIFICATE"
   :Curve25519PrivateKeyBanner "NEBULA X25519 PRIVATE KEY"
   :Curve25519PublicKeyBanner "NEBULA X25519 PUBLIC KEY"
   :EncryptedEd25519PrivateKeyBanner "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
   :Ed25519PrivateKeyBanner "NEBULA ED25519 PRIVATE KEY"
   :Ed25519PublicKeyBanner "NEBULA ED25519 PUBLIC KEY"

   :P256PrivateKeyBanner "NEBULA P256 PRIVATE KEY"
   :P256PublicKeyBanner "NEBULA P256 PUBLIC KEY"
   :EncryptedECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY"
   :ECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 PRIVATE KEY"})

(defmulti keygen
  "Implement keygeneration for supported key-pair types.
   Expects a map with a key named :key-type"
  (fn [opts] (:key-type opts)))

(defmethod keygen :ed25519
  [opts]
  (let [key-type (:key-type opts)
        kpg (doto (Ed25519KeyPairGenerator.)
              (.init (Ed25519KeyGenerationParameters. secure-random-gen)))
        kp ^AsymmetricCipherKeyPair (.generateKeyPair kpg)
        private-key ^Ed25519PrivateKeyParameters (.getPrivate kp)
        public-key ^Ed25519PublicKeyParameters (.getPublic kp)]
    {:key-type key-type
     :public-key (.getEncoded public-key)
     :private-key (.getEncoded private-key)}))

(defmethod keygen :Curve25519
  [opts]
  ;; Generate ECDH X25519
  ;;
  ;; https://github.com/bcgit/bc-java/issues/251#issuecomment-347746855
  ;; Use X25519 class to generate ECDH X25519 keys
  ;; https://github.com/bcgit/bc-java/blob/main/core/src/test/java/org/bouncycastle/math/ec/rfc7748/test/X25519Test.java#L40
  (let [key-type (:key-type opts)
        private-key (byte-array X25519/SCALAR_SIZE)
        public-key (byte-array X25519/POINT_SIZE)
        _ (do
            (X25519/generatePrivateKey secure-random-gen private-key)
            (X25519/generatePublicKey private-key 0 public-key 0))]
    {:key-type key-type
     :private-key private-key
     :public-key public-key}))

(defn p256-domain-params
  (^ECDomainParameters []
   (let [curve (ECNamedCurveTable/getParameterSpec "P-256")
         domain-params (ECDomainParameters. (-> curve (.getCurve))
                                            (-> curve (.getG))
                                            (-> curve (.getN))
                                            (-> curve (.getH))
                                            (-> curve (.getSeed)))]
     domain-params)))

(defn ^:private  key-pair-generator-p256
  "Builds a KeyPairGenerator for P256."
  (^ECKeyPairGenerator []
   (let [domain-params (p256-domain-params)
         key-params (ECKeyGenerationParameters. domain-params secure-random-gen)
         kpg ^ECKeyPairGenerator (doto (ECKeyPairGenerator.)
                                   (.init key-params))]
     kpg)))

(defmethod keygen :P256
  ;; https://pkg.go.dev/crypto/ecdh#P256
  [opts]
  (let [key-type (:key-type opts)
        kpg (key-pair-generator-p256)
        ;; https://stackoverflow.com/questions/33642100/generating-64-byte-public-key-for-dh-key-exchange-using-bouncy-castle
        kp ^AsymmetricCipherKeyPair (-> kpg (.generateKeyPair))
        pub-key-info (SubjectPublicKeyInfoFactory/createSubjectPublicKeyInfo
                      (-> kp .getPublic))
        private-key (-> ^ECPrivateKeyParameters (.getPrivate kp) (.getD) (.toByteArray))
        public-key (-> pub-key-info
                       .getPublicKeyData
                       .getBytes)]
    {:key-type key-type
     :private-key private-key
     :public-key public-key
     :pub-key-info pub-key-info}))

(defmulti write-private
  "Given a keypair map, write private key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defmulti write-public
  "Given a keypair map, write public key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defn sign-ed25519
  "Sign bytes using a private key and aED25519 algorithm."
  [key-bytes raw-bytes]
  (let [priv-key-params (Ed25519PrivateKeyParameters. key-bytes 0)
        signer ^Ed25519Signer (doto (Ed25519Signer.)
                                (.init true priv-key-params)
                                (.update raw-bytes 0 (count raw-bytes)))]
    (.generateSignature signer)))


(defn sign
  "Sign bytes using a private key"
  [curve key-bytes raw-bytes]
  (case curve
    :curve25519 (sign-ed25519 key-bytes raw-bytes)
    :P256 (f/fail "P256 signature is not supported")
    (f/fail "Curve %s is not supported" curve)))


^:rct/test
(comment

  (def ed25519-ca-key (pem/get-content (pem/read-pem! "sample-certs/sample-ca01.key")))
  (->
   (sign-ed25519 ed25519-ca-key (str->bytes "hello"))
   bytes->hex)
  ;; => "d6cab690096edf78732165093948e608346a8214df26b8efa40bab7f807cb06b64d9d1d5de979503a507c258c4277db6fb3ca5a26779bad6646c54826ae96507"
  

  (->
   (sign :curve25519 ed25519-ca-key (str->bytes "hello"))
   bytes->hex)
  ;; => "d6cab690096edf78732165093948e608346a8214df26b8efa40bab7f807cb06b64d9d1d5de979503a507c258c4277db6fb3ca5a26779bad6646c54826ae96507"
  
  ( ->
   (sign :P256 nil nil)
   f/message)
  ;; => "P256 signature is not supported" 
  
  (->
   (sign :P256aaa nil nil)
   f/message)
  ;; => "Curve :P256aaa is not supported" 
  
  )
