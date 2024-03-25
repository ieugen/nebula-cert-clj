(ns ieugen.nebula.certs
  (:require [clojure.java.io :as io]
            [ieugen.nebula.generated.cert :as cert]
            [malli.core :as m]
            [malli.error :as me]
            [malli.generator :as mg]
            [protojure.protobuf :as protojure])
  (:import (com.google.protobuf ByteString)
           (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (inet.ipaddr.ipv4 IPv4Address)
           (java.security SecureRandom Security)
           (java.time Instant)
           (java.util HexFormat)
           (org.bouncycastle.crypto Signer)
           (org.bouncycastle.crypto AsymmetricCipherKeyPair)
           (org.bouncycastle.crypto.generators ECKeyPairGenerator Ed25519KeyPairGenerator)
           (org.bouncycastle.crypto.params
            ECDomainParameters
            ECKeyGenerationParameters
            ECPrivateKeyParameters
            ECPublicKeyParameters
            Ed25519KeyGenerationParameters
            Ed25519PrivateKeyParameters
            Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)
           (org.bouncycastle.jce ECNamedCurveTable)
           (org.bouncycastle.jce.provider BouncyCastleProvider)
           (org.bouncycastle.math.ec.rfc7748 X25519)
           (org.bouncycastle.util.io.pem PemObject PemReader PemWriter)))

(set! *warn-on-reflection* true)

(Security/addProvider (BouncyCastleProvider.))

(defn security-providers
  "Get security providers registered with the JVM."
  []
  (Security/getProviders))

(def secure-random-gen (SecureRandom.))

;; https://github.com/slackhq/nebula/blob/master/cert/cert.go#L29

(def cert-banners
  {:CertBanner "NEBULA CERTIFICATE"
   :X25519PrivateKeyBanner "NEBULA X25519 PRIVATE KEY"
   :X25519PublicKeyBanner "NEBULA X25519 PUBLIC KEY"
   :EncryptedEd25519PrivateKeyBanner "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
   :Ed25519PrivateKeyBanner "NEBULA ED25519 PRIVATE KEY"
   :Ed25519PublicKeyBanner "NEBULA ED25519 PUBLIC KEY"

   :P256PrivateKeyBanner "NEBULA P256 PRIVATE KEY"
   :P256PublicKeyBanner "NEBULA P256 PUBLIC KEY"
   :EncryptedECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY"
   :ECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 PRIVATE KEY"})


(defn read-pem!
  "Read pem from file, url, etc.
   To pass String, wrap in InputStream."
  (^PemObject [pem]
   (let [pr (PemReader. (io/reader pem))]
     (.readPemObject pr))))

(defn write-pem!
  [^PemObject pem file]
  (with-open [pw (PemWriter. (io/writer file))]
    (.writeObject pw pem)))

(def RawNebulaCertificateDetails-spec
  "Malli spec for RawNebulaCertificateDetails"
  ;; TODO: Improve validation
  [:map
   [:Name string?]
    ;; TODO: Ips should be always odd
   [:Ips [:vector int?]]
   [:curve keyword?]
   [:NotBefore int?]
   [:NotAfter int?]
   [:Subnets [:vector int?]]
   [:IsCA boolean?]
   [:Issuer any?]
   [:Groups [:vector string?]]
   [:PublicKey any?]])

(def RawNebulaCertificate-spec
  "Malli spec for RawNebulaCertificate"
  ;;TODO: improve validation
  [:map {:title "RawNebulaCertificate"}
   [:Details {:title "Details"} #'RawNebulaCertificateDetails-spec
    [:Signature any?]]])

(defn valid-raw-nebula-certificate
  [raw-cert]
  (if (m/validate RawNebulaCertificate-spec raw-cert)
    raw-cert
    (let [cause (m/explain RawNebulaCertificate-spec raw-cert)]
      (throw (ex-info (str "Certificate error " (me/humanize cause))
                      {:cause cause})))))

(defn unix-timestamp->instant
  "Convert timestamp to Instant."
  [ts]
  (Instant/ofEpochSecond ts))

(defn ip-bit-mask->cidr-bits
  "Given a bit mask: 11111111111111111111111100000000
   convert it to cidr: 24"
  ;;TODO: Needs a bit more work - fix -255
  (^Integer [cidr]
   (int (- 32 (Integer/numberOfTrailingZeros cidr)))))

(def my-hex-fmt ^HexFormat (HexFormat/of))

(defn ->format-hex
  [bytes]
  (.formatHex ^HexFormat my-hex-fmt bytes))

(defn ints->ipv4
  "Convert a pair of ints from nebula storage to an IPv4Address."
  (^IPv4Address [^Integer ip ^Integer cidr]
   (let [net-prefix (ip-bit-mask->cidr-bits cidr)]
     (IPv4Address. ip net-prefix))))

(defmulti unmarshal (fn [^PemObject pem] (.getType pem)))

(defmethod unmarshal "NEBULA CERTIFICATE"
  ([^PemObject pem]
   (let [raw-cert (Cert$RawNebulaCertificate/parseFrom (.getContent pem))
         raw-cert (valid-raw-nebula-certificate raw-cert)]
     raw-cert)))

(defmethod unmarshal "NEBULA ED25519 PRIVATE KEY"
  ([^PemObject pem]
   (let [raw ()])))

(defn file->bytes
  [file]
  (with-open [xin (io/input-stream file)
              xout (java.io.ByteArrayOutputStream.)]
    (io/copy xin xout)
    (.toByteArray xout)))

(defn bytes->file
  [file ^bytes bytes]
  (with-open [f (io/output-stream file)]
    (.write f bytes)))

(defn cert-details->bytes
  "Convert protojure a RawNebulaCertificateDetails map to bytes.
  Uses double serializations since protojure has a serialization bug with
  https://github.com/protojure/lib/issues/164
  Once it's fixed we can use only protojure."
  [details]
  (let [d-bytes ^bytes (protojure/->pb details)
        cert2 (Cert$RawNebulaCertificateDetails/parseFrom d-bytes)
        d-bytes2 (.toByteArray cert2)]
    d-bytes2))

(defn ec-named-curves-seq
  "Return a sequence of EC curves."
  []
  (enumeration-seq (ECNamedCurveTable/getNames)))

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

(defmethod keygen :X25519
  [opts]
  ;; Generate EHDH X25519
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

(defmethod keygen :p256
  [opts]
  (let [key-type (:key-type opts)
        curve (ECNamedCurveTable/getParameterSpec "P-256")
        domain-params (ECDomainParameters. (-> curve (.getCurve))
                                           (-> curve (.getG))
                                           (-> curve (.getN))
                                           (-> curve (.getH))
                                           (-> curve (.getSeed)))
        key-params (ECKeyGenerationParameters. domain-params secure-random-gen)
        kpg (doto (ECKeyPairGenerator.)
              (.init key-params))
        kp (-> kpg (.generateKeyPair))
        private-key ^ECPrivateKeyParameters (.getPrivate kp)
        public-key ^ECPublicKeyParameters (.getPublic kp)]
    {:key-type key-type
     :private-key (-> private-key (.getD) (.toByteArray))
     :public-key (-> public-key (.getQ) (.getEncoded true))}))

(defmulti write-private
  "Given a keypair map, write private key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defmethod write-private :ed25519
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:X25519PrivateKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

(defmethod write-private :x25519
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:X25519PrivateKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

(defmulti write-public
  "Given a keypair map, write public key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defmethod write-public :ed25519
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:X25519PublicKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

(defmethod write-public :x25519
  [key-pair file & opts]
  (let [key-bytes (:public-key key-pair)
        banner (:X25519PublicKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

(defn verify-cert-signature
  "Verify user certificate is signed by the certificate authority.

   Return true if cert signature is valid, false either."
  [ca-cert user-cert]
  ;; Test case: Create CA with nebula, sign a certificate with nebula.
  ;; Verify the certificate is sign properly with code.
  ;; Ed25519Signer
  ;; https://github.com/slackhq/nebula/blob/master/cert/cert.go#L807
  ;; https://github.com/slackhq/nebula/blob/f8fb9759e9b049750f6a16b8531112bff814a0f7/cmd/nebula-cert/verify.go
  (let [pub-key-params (Ed25519PublicKeyParameters.
                        (get-in ca-cert [:Details :PublicKey]) 0)
        signature (get-in user-cert [:Signature])
        raw-details (get-in user-cert [:Details])
        message (cert-details->bytes raw-details)
        verifier (Ed25519Signer.)]
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature)))

(defn verify-cert-files!
  [ca-cert-file user-cert-file]
  (let [user-pem (read-pem! user-cert-file)
        ca-cert-pem (read-pem! ca-cert-file)
        user-cert (cert/pb->RawNebulaCertificate (.getContent user-pem))
        ca-cert (cert/pb->RawNebulaCertificate (.getContent ca-cert-pem))]
    ;; TODO: Implement other certificate and CA checks
    (verify-cert-signature ca-cert user-cert)))

(comment

  (verify-cert-files! "sample-certs/sample-ca01.crt" "sample-certs/sample-cert-01.crt")
  (verify-cert-files! "sample-certs/sample-ca01.crt" "ieugen.crt")

  ;; https://codesuche.com/java-examples/org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator/
  ;; https://www.demo2s.com/java/java-bouncycastle-ed25519keypairgenerator-tutorial-with-examples.html
  ;; https://www.bouncycastle.org/docs/docs1.5on/index.html
  ;; https://www.demo2s.com/java/java-bouncycastle-eckeypairgenerator-tutorial-with-examples.html
  (def k (let [kpg (doto (Ed25519KeyPairGenerator.)
                     (.init (Ed25519KeyGenerationParameters. secure-random-gen)))
               kp ^AsymmetricCipherKeyPair (.generateKeyPair kpg)]
           kp))

  (def privateKey ^Ed25519PrivateKeyParameters (.getPrivate k))

  (count (.getEncoded privateKey))
  (def X25519-kp (keygen {:key-type :X25519}))

  (count (:private-key X25519-kp))
  (count (:public-key X25519-kp))

  (write-private X25519-kp "x25519.key")
  (write-public X25519-kp "x25519.pub")

  (java.util.Arrays/equals (:private-key X25519-kp)
                           (:public-key X25519-kp))

  (bytes->file "aaa.key" (.getEncoded (:private-key k)))
  (bytes->file "aaa.pub" (.getEncoded (:public-key k)))

  (count (.getEncoded (:private-key k)))
  (count (.getEncoded (:public-key k)))


  (def ed25519-pair (keygen {:key-type :ed25519}))

  (write-private ed25519-pair "ed25519-pair.key")
  (write-public ed25519-pair "ed25519-pair.pub")

  (def p256 (keygen {:key-type :p256}))

  (bytes->file "p256.key" (:private-key p256))
  (bytes->file "p256.pub" (:public-key p256))

  )

;; TODO:
;; generăm pereche de chei pentru certificate
;; Generăm un CA
;; Semnăm cu CA
;; Validări de date
;; Generare de IP
;; Listă de certificate semnate
;; Revocare?

(comment

  (def ca-key (io/reader "aa.key"))

  (println ca-key)

  (def ca-key (read-pem! "aa.key"))

  (bean ca-key)

  (-> ca-key
      .getContent
      count)

  (def ca-crt (read-pem! "bb.crt"))
  (bean ca-crt)
  (def bb-cert (cert/pb->RawNebulaCertificate (.getContent ca-crt)))
  (count (get-in bb-cert [:Signature]))


  (def ieugen-pub (read-pem! "ieugen.pub"))
  (bean ieugen-pub)
  (def ieugen-key (read-pem! "ieugen.key"))
  ;; nebula-cert sign -ca-crt dre-ca.crt -ca-key dre-ca.key -name ieugen -in-pub ieugen.pub -ip 10.0.0.1/24
  (def ieugen-crt (read-pem! "ieugen.crt"))
  (bean ieugen-key)

  (bean ieugen-crt)
  (def ieugen-crt (cert/pb->RawNebulaCertificate (.getContent ieugen-crt)))

  ieugen-crt

  (get-in ieugen-crt [:Details :PublicKey])

  (def dre-ca-crt (cert/pb->RawNebulaCertificate (.getContent (read-pem! "dre-ca.crt"))))
  (count (get-in dre-ca-crt [:Details :PublicKey]))


  ;; Semnăm o cheie publică și facem un certificat pe care îl verificăm cu nebula-cert

  (let [dre-ca-key (.getContent (read-pem! "dre-ca.key"))
        dre-ca-crt (.getContent (read-pem! "dre-ca.crt"))
        ieugen-old-crt (.getContent (read-pem! "ieugen.crt"))
        ieugen-old-cert (Cert$RawNebulaCertificate/parseFrom ieugen-old-crt)
        dre-ca (Cert$RawNebulaCertificate/parseFrom dre-ca-crt)
        ieugen-pub (.getContent (read-pem! "ieugen.pub"))
        new-cert-details (-> (Cert$RawNebulaCertificateDetails/newBuilder)
                             (.mergeFrom (.getDetails ieugen-old-cert))
                             (.setName "ieugen-new")
                             (.build))
        details-bytes (.toByteArray new-cert-details)
        priv-key-params (Ed25519PrivateKeyParameters. dre-ca-key 0)
        signer ^Signer (doto (Ed25519Signer.)
                         (.init true priv-key-params)
                         (.update details-bytes 0 (count details-bytes)))
        signature (.generateSignature signer)
        ieugen-new-cert (-> (Cert$RawNebulaCertificate/newBuilder)
                            (.setDetails new-cert-details)
                            (.setSignature (ByteString/copyFrom signature 0 (count signature)))
                            (.build))
        pem (PemObject. "NEBULA CERTIFICATE" (.toByteArray ieugen-new-cert))]

    (write-pem! pem "ieugen-new.crt"))

  (Cert$RawNebulaCertificate/parseFrom (.getContent (read-pem! "ieugen-new.crt")))


  (let [ieugen-old-crt (.getContent (read-pem! "ieugen.crt"))
        ieugen-old-cert (Cert$RawNebulaCertificate/parseFrom ieugen-old-crt)]
    (doto (Cert$RawNebulaCertificateDetails/newBuilder)
      (.mergeFrom (.getDetails ieugen-old-cert))
      (.setName "ieugen-new")
      (.build)))

  ;; nebula-cert verify -ca dre-ca.crt -crt ieugen.crt

  ;; verificăm că certificatul este semnat de către CA
  ;; Pentru asta avem nevoie de
  ;; - semnatura din certificat
  ;; - cheia publica din certificat CA
  ;; - corpul certificatului codificat ca bytes

  (unix-timestamp->instant (get-in ieugen-crt [:Details :NotAfter]))

  (cert/pb->RawNebulaCertificate (.getContent ca-crt))

  (unmarshal ca-crt)

  (bean ca-crt)

  (def rc (valid-raw-nebula-certificate
           (cert/pb->RawNebulaCertificate (.getContent ca-crt))))

  (IPv4Address. 1684275200 (Integer. (- 32 (Integer/numberOfTrailingZeros -256))))

  (ints->ipv4 1684275200 -256)


  (let [s [:map-of {"^x-" {}}  #"^x-" :any]
        d {1 2}]
    (if (m/validate s d)
      "ok"
      (me/humanize (m/explain s d))))

  (mg/generate [:map-of {#"^x-\w*" string?
                         :min 0 :max 3}  #"^x-\w*" :string])

  (mg/generate #"^x-\w*")
  )