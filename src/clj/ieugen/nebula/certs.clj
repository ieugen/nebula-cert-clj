(ns ieugen.nebula.certs
  (:require [camel-snake-kebab.core :as csk]
            [clojure.java.io :as io]
            [clojure.set :as cset]
            [clojure.string :as str]
            [failjure.core :as f]
            [ieugen.nebula.generated.cert :as cert]
            [ieugen.nebula.net :as net]
            [ieugen.nebula.pem :as pem]
            [ieugen.nebula.time :as t]
            [jsonista.core :as j]
            [malli.core :as m]
            [malli.error :as me]
            [malli.generator :as mg]
            [protojure.protobuf :as protojure])
  (:import (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (inet.ipaddr.ipv4 IPv4Address)
           (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest SecureRandom Security)
           (java.time
            Duration
            Instant
            OffsetDateTime
            ZoneOffset)
           (java.time.format DateTimeFormatter)
           (java.util Arrays HexFormat)
           (org.bouncycastle.crypto Signer)
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
           (org.bouncycastle.math.ec.rfc7748 X25519)
           (org.bouncycastle.util.io.pem PemObject)))

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
   :Curve25519PrivateKeyBanner "NEBULA X25519 PRIVATE KEY"
   :Curve25519PublicKeyBanner "NEBULA X25519 PUBLIC KEY"
   :EncryptedEd25519PrivateKeyBanner "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
   :Ed25519PrivateKeyBanner "NEBULA ED25519 PRIVATE KEY"
   :Ed25519PublicKeyBanner "NEBULA ED25519 PUBLIC KEY"

   :P256PrivateKeyBanner "NEBULA P256 PRIVATE KEY"
   :P256PublicKeyBanner "NEBULA P256 PUBLIC KEY"
   :EncryptedECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY"
   :ECDSAP256PrivateKeyBanner "NEBULA ECDSA P256 PRIVATE KEY"})


(def RawNebulaCertificateDetails-spec
  "Malli spec for RawNebulaCertificateDetails"
  ;; TODO: Improve validation
  [:map
   [:Name string?]
   ;; TODO: Ips should be always odd:
   ;; Ips, subnets and the netmask are store as 32bit int pairs
   ;; They are stored as ip + netmask or subnet + netmask.
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

(def my-hex-fmt ^HexFormat (HexFormat/of))

(defn format-hex
  [bytes]
  (.formatHex ^HexFormat my-hex-fmt bytes))

(defn sha256sum
  [^bytes bytes]
  (let [sha256 (MessageDigest/getInstance "SHA-256")]
    (.digest sha256 bytes)))

(defn sha256sum+hex
  [^bytes bytes]
  (format-hex (sha256sum bytes)))

(defn str->bytes
  ([^String str]
   (str->bytes str StandardCharsets/UTF_8))
  ([^String str ^Charset charset]
   (.getBytes str charset)))

^:rct/test
(comment

  (format-hex (str->bytes "nebula!"))
  ;; => "6e6562756c6121"

  (sha256sum+hex (str->bytes "nebula!"))
  ;; => "c6e2203722c7a16df027a78e6a982bc505a9c92c2ec71a5f8de2d59f877db35a"
  )


(defmethod pem/unmarshal "NEBULA CERTIFICATE"
  ([^PemObject pem]
   (let [raw-cert (Cert$RawNebulaCertificate/parseFrom (pem/get-content pem))
         raw-cert (valid-raw-nebula-certificate raw-cert)]
     raw-cert)))

(defmethod pem/unmarshal "NEBULA ED25519 PRIVATE KEY"
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

(defn marshal-raw-cert
  "Convert protojure a RawNebulaCertificate map to bytes.
  Uses double serializations since protojure has a serialization bug with
  https://github.com/protojure/lib/issues/164
  Once it's fixed we can use only protojure."
  [details]
  (let [d-bytes ^bytes (protojure/->pb details)
        cert2 (Cert$RawNebulaCertificate/parseFrom d-bytes)
        d-bytes2 (.toByteArray cert2)]
    d-bytes2))

(defn marshal-raw-cert-details
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

(defmethod write-private :Curve25519
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:Curve25519PrivateKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (pem/write-pem! pem file)))

(defmethod write-private :P256
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:P256PrivateKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (pem/write-pem! pem file)))

(defmulti write-public
  "Given a keypair map, write public key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defmethod write-public :Curve25519
  [key-pair file & {:keys [file-mode] :as _opts}]
  (let [key-bytes (:public-key key-pair)
        banner (:Curve25519PublicKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (pem/write-pem! pem file)))

(defmethod write-public :P256
  [key-pair file & {:keys [file-mode] :as _opts}]
  (let [key-bytes (:public-key key-pair)
        banner (:P256PublicKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (pem/write-pem! pem file)))

(def NebulaCAPool-spec
  [:map {:title "NebulaCAPool - holds CA certs and cert block list"}
   [:CAs [:map string?]]
   [:cert-block-list :sequential]])

(defn ca-pool->add-ca
  "Verify a CA and add it to the pool."
  [ca-pool ca]
  ;;TODO: verify pool with malli
  ;;TODO: verify CA with malli
  (let [details (:Details ca)
        {:keys [IsCA PublicKey Name]} details]
    (when-not IsCA
      (throw (ex-info (str "Certificate is not a CA" Name) {:ca ca})))

    (assoc-in ca-pool [:CAs "a"]  ca)))

(defn get-ca-for-cert
  "Find the CA that issues the cert in the CA pool.
   Return the CA or nil if not found."
  [ca-pool user-cert]
  (let [issuer (get-in user-cert [:Details :Issuer])
        ca-map (:CAs ca-pool)
        issuer-ca (get ca-map issuer)]
    (when-not issuer
      (ex-info "Missing issuer in certificate" {:cert user-cert}))
    (if issuer-ca
      issuer-ca
      ;; Maybe throw if issuer CA is not found?
      #_(ex-info "CA not found for certificate" {:cert user-cert})
      nil)))

(defn block-list-fingerprint
  "Add a fingerpint to the cert block-list.
   Return a new ca-pool."
  [ca-pool fingerprint]
  (assoc-in ca-pool [:cert-block-list fingerprint] {}))

(defn get-fingerprints
  "Return a vector of CA fingerprints."
  [ca-pool]
  (vec (keys (:cert-block-list ca-pool))))

(defn ^:deprecated verify-cert-signature
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
        message (marshal-raw-cert-details raw-details)
        verifier (Ed25519Signer.)]
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature)))

(defn verify-signature-ed25519
  "Verify crypto signature for Curve25519.
   Return true if cert signature is valid, false other way."
  [user-cert pub-key-bytes]
  (let [signature (get-in user-cert [:Signature])
        raw-details (get-in user-cert [:Details])
        message (marshal-raw-cert-details raw-details)
        pub-key-params (Ed25519PublicKeyParameters. pub-key-bytes 0)
        verifier (Ed25519Signer.)]
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature)))

(defn verify-signature-p256
  "Verify crypto signature for Curve P256.
   Return true if cert signature is valid, false other way."
  ;; https://stackoverflow.com/questions/30445997/loading-raw-64-byte-long-ecdsa-public-key-in-java/30471945#30471945
  [user-cert ^bytes pub-key-bytes]
  (let [{:keys [Details Signature]} user-cert
        message (marshal-raw-cert-details Details)
        domain-params (p256-domain-params)
        curve-params (CustomNamedCurves/getByName "P-256")
        domain-params (p256-domain-params)
        ;; q (-> curve-params .getCurve .getQ)
        ;; p256-asn-primitive (-> curve-params .toASN1Primitive .toASN1BitString)
        ;; pub-key-info (SubjectPublicKeyInfo. (.getCurve curve-params) pub-key-bytes)
        ]
    (throw (UnsupportedOperationException. "Not implemented"))))


(comment

  (def p256-pub (.getContent (pem/read-pem! "sample-certs/P256.pub")))
  (def p256-cert (-> (pem/read-pem! "sample-certs/P256.crt")
                     .getContent
                     cert/pb->RawNebulaCertificate))

  (def x9ec (verify-signature-p256 p256-cert p256-pub))

  (ECNamedCurveTable/getParameterSpec "P-256"))

(defn check-signature
  "Check if a certificate is signed with the provided public key"
  ;; TODO: Implement as multimethod ?
  [cert pub-key]
  (let [curve (get-in cert [:Details :Curve])]
    (case curve
      "CURVE25519"
      (verify-signature-ed25519 cert pub-key)
      "P256"
      (verify-signature-p256 cert pub-key)
      :default  false)))

(defn marshal*
  "Convert RawNebulaCertificate to bytes.
  Include only :Details and :Signature "
  [cert]
  (let [c (select-keys cert [:Details :Signature])]
    (marshal-raw-cert c)))

(defn cert->hex-sha256sum
  [cert]
  (let [b (marshal* cert)
        sum256 (sha256sum+hex b)]
    sum256))

(defn cert-is-block-listed?
  "Check if a certificate is in the certificate block list.
   Return true if it is, false otherwise."
  [ca-pool cert]
  (let [block-list (:cert-block-list ca-pool)
        hex-sha (cert->hex-sha256sum cert)]
    (contains? block-list hex-sha)))

(defn expired-cert?
  [cert ^Instant time]
  (let [details (:Details cert)
        {:keys [NotBefore NotAfter]} details
        not-before (t/unix-timestamp->instant NotBefore)
        not-after (t/unix-timestamp->instant NotAfter)]
    (t/expired? not-before not-after time)))

(defn check-root-constrains
  "Throw an error if cert violates constraints
   set by the CA that signed it: ips, groups, subnets, etc"
  [cert signer]
  (let [signer-not-after (get-in signer [:Details :NotAfter])
        signer-not-after ^Instant (t/unix-timestamp->instant signer-not-after)
        cert-not-after (get-in cert [:Details :NotAfter])
        cert-not-after ^Instant (t/unix-timestamp->instant cert-not-after)
        valid-after-signer? (-> cert-not-after (.isAfter signer-not-after))]
    ;; Make sure cert was not valid before signer
    (when valid-after-signer?
      (throw (ex-info "Certificate expires after signing certificate"
                      {:cert cert :ca signer}))))
  (let [signer-not-before (get-in signer [:Details :NotBefore])
        signer-not-before ^Instant (t/unix-timestamp->instant signer-not-before)
        cert-not-before (get-in cert [:Details :NotBefore])
        cert-not-before ^Instant (t/unix-timestamp->instant cert-not-before)
        valid-before-signer? (-> cert-not-before (.isBefore signer-not-before))]
    ;; Make sure cert isn't valid after signer
    (when valid-before-signer?
      (throw (ex-info "Certificate is valid before signing certificate"
                      {:cert cert :ca signer}))))

  (let [signer-groups (get-in signer [:Details :Groups])
        gcount (count signer-groups)]
    ;; If the signer has limited set of groups,
    ;; make sure cert only contains a subset
    (when (> gcount 0)
      (let [signer-groups (set signer-groups)
            cert-groups (set (get-in cert [:Details :Groups]))
            diff (cset/difference cert-groups signer-groups)]
        (when (> (count diff) 0)
          (throw (ex-info (str "Certificate contains groups not present in the signing ca"
                               diff) {:cert cert :ca signer}))))))
  (let [signer-ips (get-in signer [:Details :Ips])]
    ;; If the signer has a limited set of ip ranges to issue from,
    ;; make sure the cert only contains a subset
    (when (< 0 signer-ips)
      (let [signer-ips (net/int-pairs->ipv4 signer-ips)
            ips (get-in cert [:Details :Ips])
            ips (net/int-pairs->ipv4 ips)
            matches (map #(net/net-match? % signer-ips) ips)
            ip-matches? (some true? matches)]
        (when-not ip-matches?
          (throw (ex-info "Certificate contained an ip assignment outside the limitations of the signing ca"
                          {:ips (map str ips)
                           :signer-ips (map str signer-ips)}))))))
  (let [signer-subnets (get-in signer [:Details :Subnets])]
  ;; If the signer has a limited set of subnet ranges to issue from,
  ;; make sure the cert only contains a subset
    (when (< 0 signer-subnets)
      (let [signer-subnets (net/int-pairs->ipv4 signer-subnets)
            subnets (get-in cert [:Details :Subnets])
            subnets (net/int-pairs->ipv4 subnets)
            matches (map #(net/net-match? % signer-subnets) subnets)
            subnet-matches? (some true? matches)]
        (when-not subnet-matches?
          (throw (ex-info "certificate contained a subnet assignment outside the limitations of the signing ca"
                          {:subnets (map str subnets)
                           :signer-subnets (map str signer-subnets)})))))

    ;; if we reach this point, it matches
    true))


(defn verify
  "Verify a certificate is valid:
   - expiration
   - cert block list
   - signature
   - group membership
   - etc"
  [ca-pool cert time]
  (let [block-listed? (cert-is-block-listed? ca-pool cert)
        signer (get-ca-for-cert ca-pool cert)
        signer-pubkey (get-in signer [:Details :PublicKey])
        expired-ca? (expired-cert? signer time)
        expired-cert? (expired-cert? cert time)]
    (when block-listed?
      (throw (ex-info "Certificate is blocked" {:cert cert})))
    (when expired-ca?
      (throw (ex-info "CA expired" {:cert signer})))
    (when expired-cert?
      (throw (ex-info "Cert expired" {:cert cert})))
    (when-not (check-signature cert signer-pubkey)
      (throw (ex-info "Signature mismatch" {:ca signer
                                            :public-key (format-hex signer-pubkey)
                                            :cert cert})))
    (check-root-constrains cert signer)))


(defn pem->RawNebulaCertificate
  "Parse a nebula cert from a ^PemObject"
  [^PemObject pem]
  (cert/pb->RawNebulaCertificate (pem/get-content pem)))

(defn ^:deprecated verify-cert-files!
  "Verify a certificate is valid and issued by a specific CA.
  The CA file can contain multiple certs.

  TODO: Implement support for P256 check."
  [ca-cert-file user-cert-file]
  (when (str/blank? ca-cert-file)
    (throw (ex-info "CA cert file path is invalid"
                    {:path ca-cert-file})))
  (when (str/blank? user-cert-file)
    (throw (ex-info "User cert path is invalid"
                    {:path user-cert-file})))
  (let [user-pem (pem/read-pem! user-cert-file)
        ca-cert-pems (pem/read-pems! ca-cert-file)
        user-cert (pem->RawNebulaCertificate user-pem)
        ca-certs (into [] (map pem->RawNebulaCertificate ca-cert-pems))
        ;; Find CA of cert in list by issuer
        ca-cert (first ca-certs)]
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
  (def X25519-kp (keygen {:key-type :Curve25519}))

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

  (def p256 (keygen {:key-type :P256}))

  (bytes->file "p256.key" (:private-key p256))
  (bytes->file "p256.pub" (:public-key p256)))

;; TODO:
;; generăm pereche de chei pentru certificate
;; Generăm un CA
;; Semnăm cu CA
;; Validări de date
;; Generare de IP
;; Listă de certificate semnate
;; Revocare?

(defn java-instant->iso-str
  "Format a java ^Instant to ISO DateTime"
  [^Instant instant]
  (let [d (OffsetDateTime/ofInstant instant (ZoneOffset/systemDefault))]
    (.format d DateTimeFormatter/ISO_OFFSET_DATE_TIME)))

(defn cert-fingerprint
  "Compute sha256 fingerprint as hex string."
  [raw-cert]
  (sha256sum+hex (marshal-raw-cert raw-cert)))

(defn RawNebulaCertificate->NebulaCert4Print
  "Convert a raw nebula cert to a nebula cert.
   Data types are parsed:
   - timestamp -> Instant
   - ip ints -> Ipv4Address"
  [raw-cert]
  (let [{:keys [Details Signature]} raw-cert
        {:keys [Name curve IsCA NotAfter NotBefore
                Subnets Ips Groups
                ^bytes PublicKey
                ^bytes Issuer]} Details
        ips (into [] (map str (net/int-pairs->ipv4 Ips)))
        subnets (into [] (map str (net/int-pairs->ipv4 Subnets)))
        not-after (t/unix-timestamp->instant NotAfter)
        not-after (java-instant->iso-str not-after)
        not-before (t/unix-timestamp->instant NotBefore)
        not-before (java-instant->iso-str not-before)
        curve (str/upper-case (name curve))
        Issuer (format-hex Issuer)
        PublicKey (format-hex PublicKey)
        Signature (format-hex Signature)
        d {:Name Name
           :curve curve
           :IsCA IsCA
           :NotAfter not-after
           :NotBefore not-before
           :Ips ips
           :Subnets subnets
           :Issuer Issuer
           :Groups Groups
           :PublicKey PublicKey}]
    {:Details d
     :Signature Signature}))

(defn RawNebulaCertificate->NebulaCertificate
  "Convert a raw nebula cert to a nebula cert.
   Data types are parsed:
   - timestamp -> Instant
   - ip ints -> Ipv4Address"
  [raw-cert]
  (let [{:keys [Details Signature]} raw-cert
        {:keys [Name curve IsCA NotAfter NotBefore
                Subnets Ips Groups
                ^bytes PublicKey
                ^bytes Issuer]} Details
        ips (into [] (net/int-pairs->ipv4 Ips))
        subnets (into [] (net/int-pairs->ipv4 Subnets))
        not-after (t/unix-timestamp->instant NotAfter)
        not-before (t/unix-timestamp->instant NotBefore)
        d {:Name Name
           :curve curve
           :IsCA IsCA
           :NotAfter not-after
           :NotBefore not-before
           :Ips ips
           :Subnets subnets
           :Issuer Issuer
           :Groups Groups
           :PublicKey PublicKey}]
    {:Details d
     :Signature Signature}))
(defn NebulaCertificate->RawNebulaCertificate
  "Convert a raw nebula cert to a nebula cert.
   Data types are parsed:
   - timestamp -> Instant
   - ip ints -> Ipv4Address"
  [raw-cert]
  (let [{:keys [Details Signature]} raw-cert
        {:keys [Name curve IsCA NotAfter NotBefore
                Subnets Ips Groups
                ^bytes PublicKey
                ^bytes Issuer]} Details
        ips (into [] (net/addresses->ints Ips))
        subnets (into [] (net/addresses->ints Subnets))
        not-after (t/instant->unix-timestamp NotAfter)
        not-before (t/instant->unix-timestamp NotBefore)
        ;; Curve (str/upper-case (name Curve))
        ;; Issuer (format-hex Issuer)
        ;; PublicKey (format-hex PublicKey)
        ;; Signature (format-hex Signature)
        d {:Name Name
           :curve curve
           :IsCA IsCA
           :NotAfter not-after
           :NotBefore not-before
           :Ips ips
           :Subnets subnets
           :Issuer Issuer
           :Groups Groups
           :PublicKey PublicKey}]
    {:Details d
     :Signature Signature}))

(def cert-json-mapper
  (j/object-mapper
   {:encode-key-fn (fn [k] (csk/->camelCase k))}))

(defn format-coll-str
  "Format a collection for print: Ips, Subnets, Groups"
  ([coll coll-type]
   (format-coll-str coll coll-type false))
  ([coll coll-type quote-item]
   (let [format-fn (if quote-item
                     (fn [item] (str "\t\t\t\"" item "\"\n"))
                     (fn [item] (str "\t\t\t" item "\n")))]
     (if (> (count coll) 0)
       (str "\t\t" coll-type ": [\n"
            (str/join "" (map format-fn coll))
            "\t\t]\n")
        ;; no items
       (str "\t\t" coll-type ":[]\n")))))

(defn cert-str
  [cert]
  (if-not cert
    "NebulaCertificate {}\n"
    (let [{:keys [Details Signature Fingerprint]} cert
          {:keys [Name Ips Subnets Groups
                  NotBefore NotAfter IsCA
                  Issuer PublicKey curve]} Details]
      (str "NebulaCertificate {\n"
           "\tDetails {\n"
           "\t\tName: " Name "\n"
           (format-coll-str Ips "Ips")
           (format-coll-str Subnets "Subnets")
           (format-coll-str Groups "Groups" true)
           "\t\tNot before: " NotBefore "\n"
           "\t\tNot after: " NotAfter "\n"
           "\t\tIs CA: " IsCA "\n"
           "\t\tIssuer: " Issuer "\n"
           "\t\tPublic key: " PublicKey "\n"
           "\t\tCurve: " curve " \n"
           "\t}\n"
           "\tFingerprint: " Fingerprint "\n"
           "\tSignature: " Signature "\n"
           "}"))))

(defn cli-print-cert
  "CLI command - print details from a certificate."
  [cert-path & {:keys [json out-qr] :as opts}]
  (let [cert-pem (pem/read-pem! cert-path)
        cert (pem->RawNebulaCertificate cert-pem)
        fingerpint (cert-fingerprint cert)
        c (RawNebulaCertificate->NebulaCert4Print cert)
        c (assoc c :Fingerprint fingerpint)]
    (if json
      (j/write-value-as-string c cert-json-mapper)
      (cert-str c))))

(comment

  (def cert (pem->RawNebulaCertificate
             (pem/read-pem! "sample-certs/sample-ca01.crt")))
  cert

  (-> cert
      :Details
      :Issuer
      format-hex)

  (-> cert
      :Details
      :PublicKey
      format-hex)

  (-> (RawNebulaCertificate->NebulaCertificate cert))

  (-> (RawNebulaCertificate->NebulaCertificate cert)
      (NebulaCertificate->RawNebulaCertificate))


  )

(defn cli-keygen
  "CLI command - generate nebula keys."
  [curve out-key out-pub & _opts]
  (let [curve (curve-str-kw curve)
        key-pair (keygen {:key-type curve})]
    (write-private key-pair out-key)
    (write-public key-pair out-pub)))

(comment

  (cli-keygen "25519" "25519.key" "25519.pub")
  (cli-keygen "P256" "P256.key" "P256.pub"))


(defn ed25519-25519-check-private-key
  "For a given ed25519 key pair, check if they match.
   Return true when private key and public key are a pair.
   Return a failure object when not."
  [^bytes private-key ^bytes public-key]
  (if (not= 64 (count private-key))
    (f/fail "key was not 64 bytes, is invalid ed25519 private key")
    (let [private-key-params (Ed25519PrivateKeyParameters. private-key 0)
          pub-key2 ^bytes (-> private-key-params .generatePublicKey .getEncoded)]
      (if (Arrays/equals public-key pub-key2)
        true
        (f/fail "public key in cert and private key supplied don't match")))))

^:rct/test
(comment

  (def my-ed25519-private-key (-> (pem/read-pem! "sample-certs/sample-ca01.key")
                                  pem/get-content))

  (def my-ed25519-ca-pem (pem/read-pem! "sample-certs/sample-ca01.crt"))

  (def my-ed25519-ca-cert (pem->RawNebulaCertificate my-ed25519-ca-pem))
  (def my-ed25519-pub-key (-> my-ed25519-ca-cert :Details :PublicKey))

  (ed25519-25519-check-private-key my-ed25519-private-key my-ed25519-pub-key)
  ;; => true

  (ed25519-25519-check-private-key (str->bytes "Invalid key is not 64 bytes long") nil)
  ;; => #failjure.core.Failure{:message "key was not 64 bytes, is invalid ed25519 private key"}

  (ed25519-25519-check-private-key my-ed25519-private-key
                                   (str->bytes "Invalid public key"))
  ;; => #failjure.core.Failure{:message "public key in cert and private key supplied don't match"}
  )


(defn curve25519-private->public
  "Get the public key from the bytes of a private Curve25519 key.
   Return the public key bytes on success.
   Return a ^failjure.core.Failure otherwise."
  [^bytes private-key]
  (f/try*
   (let [public-key (byte-array X25519/POINT_SIZE)
         _ (X25519/generatePublicKey private-key 0 public-key 0)]
     public-key)))


(defn private-key->public-key
  "Attempt to extract the public key from the private key bytes
   The curve type is given.
   Return the public key bytes on success.
   Return a ^failjure.core.Failure on failure."
  [^bytes private-key ^String curve]
  (f/try-all
   [pub (case curve
          "X25519" (curve25519-private->public private-key)
          "P256" (f/fail "P256 curve is not implemented yet")
          (f/fail "Invalid curve %s" curve))]
   pub))

^:rct/test
(comment

  (let [private-key (pem/get-content (pem/read-pem! "sample-certs/ecdh-25519-01.key"))
        pub-key (-> (pem/read-pem! "sample-certs/ecdh-25519-01.pub") pem/get-content)
        pp-key (private-key->public-key private-key "X25519")]
    (Arrays/equals pub-key pp-key))
  ;; => true

  (private-key->public-key (str->bytes "") "invalid_curve")
  ;; => #failjure.core.Failure{:message "Invalid curve invalid_curve"}

  (private-key->public-key (str->bytes "") "P256")
  ;; => #failjure.core.Failure{:message "P256 curve is not implemented yet"}

  (f/message (private-key->public-key (str->bytes "") "X25519"))
  ;; => "arraycopy: last source index 32 out of bounds for byte[0]"
  )

(defn check-ca-keys-match
  "Check if the keys match for a CA private key and public key pair."
  [^bytes private-key ^bytes public-key ^String curve]
  (case curve
    "curve25519" (ed25519-25519-check-private-key private-key public-key)
    "P256" (f/fail "P256 curve is not implemented yet")
    (f/fail "Invalid curve %s" curve)))
(defn check-non-ca-keys-match
  "Check keys match for non CA private key and public key pair."
  [^bytes private-key ^bytes public-key ^String curve]
  (f/try-all [^bytes pub-key (private-key->public-key private-key curve)]
             (if (Arrays/equals pub-key public-key)
               true
               (f/fail "Public key in cert and private key supplied don't match"))))

(defn verify-private-key
  "Check that the public key in the Nebula certificate and a supplied private key match.
   Return true in case of match.
   Return a ^failjure.core.Failure on failure."
  ;; Port of https://github.com/slackhq/nebula/blob/bbb15f8cb1ecdc7e423ffd1a85a3fc8c0898bf95/cert/cert.go#L694
  [ca-cert ^String key-curve ^bytes private-key]
  (let [details (:Details ca-cert)
        {:keys [Curve IsCa PublicKey]} details
        private-key-ok true]
    (f/try-all
     [_ (when (not= key-curve Curve)
          (f/fail "Curve in cert: %s and key: %s don't match" Curve key-curve))
      _ (if IsCa
          ;; check CA keys
          (check-ca-keys-match private-key PublicKey key-curve)
          ;; not CA - chek keys the other way
          (check-non-ca-keys-match private-key PublicKey key-curve))]
     ;; keys are ok
     private-key-ok)))

(defn compute-cert-not-after
  "Cert NotAfter value is computed like:
   - now + duration - when a duration is specified
   - one second before given expiration of not-after

   Does not check if now + duration is past not-after."
  [^Instant now ^Instant not-after ^Duration duration]
  (if (t/negative-or-zero-duration? duration)
    (.minusSeconds not-after 1)
    (.plus now duration)))

^:rct/test
(comment

  (def my-now1 (Instant/parse "2024-04-10T09:00:00Z"))
  (def my-not-after1 (.plusSeconds my-now1 300))

  (str (compute-cert-not-after my-now1 my-not-after1 Duration/ZERO))
  ;; => "2024-04-10T09:04:59Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT-1s")))
  ;; => "2024-04-10T09:04:59Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT10s")))
  ;; => "2024-04-10T09:00:10Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT350s")))
  ;; => "2024-04-10T09:05:50Z"

  )

(defn parse-groups
  "Parse string of group names separated by colon , .
   Return a collection of groups.
   Trim group names"
  [^String groups-str]
  (when groups-str
    (let [groups (str/split groups-str #",")
          groups (map str/trim groups)]
      (into [] (filter #(not (str/blank? %)) groups)))))

^:rct/test
(comment

  (parse-groups nil)
  ;; => nil

  (parse-groups "")
  ;; => []

  (parse-groups "a")
  ;; => ["a"]

  (parse-groups "a,")
  ;; => ["a"]

  (parse-groups "a , b")
  ;; => ["a" "b"]

  )

(defn parse-subnets
  "Parse a string of subnets to a vector of ^IPv4Address .
   Strings must be valid network addresses: ipv4 addres + network prefix
   In case of failure returns a failjure.core.Failure "
  [^String subnets-str]
  (when-not (str/blank? subnets-str)
    (let [subnets (str/split subnets-str #",")
          subnets (map str/trim subnets)
          subnets (map net/parse-ipv4-cidr subnets)
          failed (filter f/failed? subnets)
          failed? (pos-int? (count failed))]
      (if failed?
        (f/fail "Failed to parse subnets: %s. %s" subnets-str
                (f/message (first failed)))
        (into [] subnets)))))

^:rct/test
(comment

  (parse-subnets nil)
  ;; => nil

  (parse-subnets "")
  ;; => nil

  (parse-subnets "a")
  ;; => #failjure.core.Failure{:message "Failed to parse subnets: a. a IP address error: IP is not IPv4"}

  (parse-subnets "192.168.0.1")
  ;; => #failjure.core.Failure{:message "Failed to parse subnets: 192.168.0.1. Not a network address: 192.168.0.1"}

  (parse-subnets "192.168.0.1/16,a")
  ;; => #failjure.core.Failure{:message "Failed to parse subnets: 192.168.0.1/16,a. a IP address error: IP is not IPv4"}

  (->> (parse-subnets "192.168.0.1/16,192.168.0.1/22")
       (map str))
  ;; => ("192.168.0.1/16" "192.168.0.1/22")

  (->> (parse-subnets "192.168.0.1/16,2001:db8::2:1/64")
       (map str))
  ;; => ("[:message \"Failed to parse subnets: 192.168.0.1/16,2001:db8::2:1/64. 2001:db8::2:1/64 IP address error: IP is not IPv4\"]")

  )

(defn read-pub-key
  [file curve]
  (f/try-all [pub (pem/read-pem! file)
              _curve_ok? (when (not= (pem/get-type pub) curve)
                           (f/fail "Curve of %s does not match CA curve:"
                                   file curve))]
             pub))


(defn cert-name [name] (str name ".crt"))
(defn private-key-name [name] (str name ".key"))

(defn public-key-name [name] (str name ".pub"))

(defn file-exists? [f] (-> (io/file f) (.exists)))

^:rct/test
(comment

  (file-exists? "not-existing-file")
  ;; => false

  (file-exists? ".gitignore")
  ;; => true

  )

(defn sign-cert
  [nebula-cert ^String curve ^bytes private-key]
  (f/try-all [{:keys [Details Issueer]} nebula-cert
              {:keys [Curve]} Details
              _curve_ok? (when-not (= curve Curve)
                           (f/fail "Curve in cert and private key supplied don't match"))]
             ""))

(defn cli-sign
  "Sign a user certificate given a path to CA key and cert and some options.
   TODO: Implement passowrd reading and CA key decryption."
  [ca-crt-path ca-key-path name ip opts]
  (f/try-all [{:keys [duration groups out-crt out-key subnets in-pub]
               :or {out-key (private-key-name name)
                    out-crt (cert-name name)}} (:flags opts)
              ca-key-pem (pem/read-pem! ca-key-path)
              ca-key-bytes (pem/get-content ca-key-pem)
              ca-curve (pem/get-type ca-key-pem)
              _ (when (= ca-curve "P256")
                  (f/fail  "P256 curve not implemented."))
              ca-cert-pem (pem/read-pem! ca-crt-path)
              raw-ca-cert (pem->RawNebulaCertificate ca-cert-pem)
              ca-cert (RawNebulaCertificate->NebulaCert4Print raw-ca-cert)
              not-after (get-in ca-cert [:Details :NotAfter])
              _keys_match (verify-private-key ca-cert ca-curve ca-key-bytes)
              issuer (cert-fingerprint raw-ca-cert)
              now (Instant/now)
              _expired (when (expired-cert? ca-cert now)
                         (f/fail "ca certificate is expired"))
              cert-not-after (compute-cert-not-after now not-after duration)
              ip (net/parse-ipv4-cidr ip)
              groups (parse-groups groups)
              subnets (parse-subnets subnets)
              cert-pub (read-pub-key in-pub ca-curve)
              new-cert {:Details {:Name name
                                  :Ips [ip]
                                  :Groups groups
                                  :Subnets subnets,
                                  :NotBefore now
                                  :NotAfter cert-not-after
                                  :PublicKey (pem/get-content cert-pub)
                                  :IsCA false
                                  :Issuer issuer
                                  :Curve ca-curve}}
              _new-cert (check-root-constrains new-cert ca-cert)
              _out-crt (when (file-exists? out-crt)
                         (f/fail "Refusing to overwrite existing cert: %s" out-crt))
              details-bytes ""
              new-cert-details ""
              priv-key-params (Ed25519PrivateKeyParameters. ca-key-bytes 0)
              signer ^Signer (doto (Ed25519Signer.)
                               (.init true priv-key-params)
                               (.update details-bytes 0 (count details-bytes)))
              ;; signature (.generateSignature signer)
              pem-data (marshal-raw-cert new-cert-details)
              pem (PemObject. "NEBULA CERTIFICATE" pem-data)]
             (pem/write-pem! pem out-crt)))

(comment




  (f/attempt-all [x 2
                  y (+ x 4)]
                 y
                 (f/when-failed [e]
                                (f/message e)))


  (f/try-all [a "a"
              b (str a "x")
              c (throw (ex-info (str "fail" a b) {}))
              d (str "c " c)]
             d)


  (def ca-key (io/reader "aa.key"))

  (println ca-key)

  (def ca-key (pem/read-pem! "aa.key"))

  (bean ca-key)

  (-> ca-key
      .getContent
      count)

  (def ca-crt (pem/read-pem! "bb.crt"))
  (bean ca-crt)
  (def bb-cert (cert/pb->RawNebulaCertificate (.getContent ca-crt)))
  (count (get-in bb-cert [:Signature]))


  (def ieugen-pub (pem/read-pem! "ieugen.pub"))
  (bean ieugen-pub)
  (def ieugen-key (pem/read-pem! "ieugen.key"))
  ;; nebula-cert sign -ca-crt dre-ca.crt -ca-key dre-ca.key -name ieugen -in-pub ieugen.pub -ip 10.0.0.1/24
  (def ieugen-crt (pem/read-pem! "ieugen.crt"))
  (bean ieugen-key)

  (bean ieugen-crt)
  (def ieugen-crt (cert/pb->RawNebulaCertificate (.getContent ieugen-crt)))

  ieugen-crt

  (get-in ieugen-crt [:Details :PublicKey])

  (def dre-ca-crt (cert/pb->RawNebulaCertificate (.getContent (pem/read-pem! "dre-ca.crt"))))
  (count (get-in dre-ca-crt [:Details :PublicKey]))


  ;; Semnăm o cheie publică și facem un certificat pe care îl verificăm cu nebula-cert



  (Cert$RawNebulaCertificate/parseFrom (.getContent (pem/read-pem! "ieugen-new.crt")))


  (let [ieugen-old-crt (.getContent (pem/read-pem! "ieugen.crt"))
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

  (t/unix-timestamp->instant (get-in ieugen-crt [:Details :NotAfter]))

  (cert/pb->RawNebulaCertificate (.getContent ca-crt))

  (pem/unmarshal ca-crt)

  (bean ca-crt)

  (def rc (valid-raw-nebula-certificate
           (cert/pb->RawNebulaCertificate (.getContent ca-crt))))

  (IPv4Address. 1684275200 (Integer. (- 32 (Integer/numberOfTrailingZeros -256))))

  (net/ints->ipv4 1684275200 -256)


  (let [s [:map-of {"^x-" {}}  #"^x-" :any]
        d {1 2}]
    (if (m/validate s d)
      "ok"
      (me/humanize (m/explain s d))))

  (mg/generate [:map-of {#"^x-\w*" string?
                         :min 0 :max 3}  #"^x-\w*" :string])

  (mg/generate #"^x-\w*"))