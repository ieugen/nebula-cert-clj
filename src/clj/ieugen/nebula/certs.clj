(ns ieugen.nebula.certs
  (:require [clojure.java.io :as io]
            [clojure.set :as cset]
            [clojure.string :as str]
            [ieugen.nebula.generated.cert :as cert]
            [jsonista.core :as j]
            [camel-snake-kebab.core :as csk]
            [malli.core :as m]
            [malli.error :as me]
            [malli.generator :as mg]
            [protojure.protobuf :as protojure])
  (:import (com.google.protobuf ByteString)
           (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (inet.ipaddr IPAddress$IPVersion IPAddressString)
           (inet.ipaddr.ipv4 IPv4Address)
           (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest SecureRandom Security)
           (java.time Instant OffsetDateTime ZoneOffset)
           (java.time.format DateTimeFormatter)
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

(defn read-pems!
  "Read all PEMs from file, url, etc.
   To pass String, wrap in InputStream.

   Return a vector of ^PemObject"
  ([pem]
   (let [pr (PemReader. (io/reader pem))]
     (loop [po ^PemObject (.readPemObject pr)
            result []]
       (if-not po
         result
         (recur (.readPemObject pr)
                (conj result po)))))))

^:rct/test
(comment

  (count (read-pems! "sample-certs/multiple-ca.crt")) ;;=> 2
  )

(defn write-pem!
  "Write a PEM file to disk.
   TODO: Implement write with specific file permissions ?!"
  [^PemObject pem file]
  (with-open [pw (PemWriter. (io/writer file))]
    (.writeObject pw pem)))

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

(defn unix-timestamp->instant
  "Convert timestamp to Instant."
  [ts]
  (Instant/ofEpochSecond ts))

(defn ip-bit-mask->cidr-bits
  "Given a bit mask: 11111111111111111111111100000000
   convert it to cidr: 24.
   Throws exception if int has discontiguos 1's and
   if CIDR is outside 0-32 bits"
  (^Integer [cidr]
   (let [leading-ones (int (- 32 (Integer/numberOfTrailingZeros cidr)))
         bit-count (Integer/bitCount cidr)
         same-bit-count? (= bit-count leading-ones)]
     ;; Network masks need to ahve contiguos number of 1's followed by 0's
     ;; https://datatracker.ietf.org/doc/html/rfc1519#section-4.2
     (when-not same-bit-count?
       (throw (ex-info (str "Integer value is not a network mask: "
                            (Integer/toBinaryString cidr)) {:cidr cidr})))
     (when (or (< leading-ones 0)
               (> leading-ones 32))
       (throw (ex-info (str "Integer valus is outside normal CIDR range "
                            leading-ones) {:cidr cidr
                                           :bit-count bit-count})))
     leading-ones)))

^:rct/test
(comment

  (try
    (ip-bit-mask->cidr-bits -3)
    (catch Exception e
      (ex-message e)))
  ;; => "Integer value is not a network mask: 11111111111111111111111111111101"

  (ip-bit-mask->cidr-bits -256)  ;; => 24
  (ip-bit-mask->cidr-bits -1)  ;; => 32
  (ip-bit-mask->cidr-bits 0)
  ;; => 0

  )

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

(defn ints->ipv4
  "Convert a pair of ints from nebula storage to an IPv4Address."
  (^IPv4Address [^Integer ip ^Integer cidr]
   (let [net-prefix (ip-bit-mask->cidr-bits cidr)]
     (IPv4Address. ip net-prefix))))

(defn int-pairs->ipv4
  "Convert a sequence of nebula IP/netmask paris to
   a sequence of ^IPv4Address"
  [ips+netmasks]
  (when (odd? (count ips+netmasks))
    (throw (ex-info (str "Ips should contain an even number of values "
                         (count ips+netmasks))
                    {:ips ips+netmasks})))
  (for [[ip mask] (partition 2 (map int ips+netmasks))]
    (ints->ipv4 ip mask)))

^:rct/test
(comment

  (map str (int-pairs->ipv4 nil))
  ;; => ()

  (map str (int-pairs->ipv4 []))
  ;; => ()

  (map str (int-pairs->ipv4 [0 -256 1 -256 2 -256]))
  ;; => ("0.0.0.0/24" "0.0.0.1/24" "0.0.0.2/24")

  )

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

(defn cert->bytes
  "Convert protojure a RawNebulaCertificate map to bytes.
  Uses double serializations since protojure has a serialization bug with
  https://github.com/protojure/lib/issues/164
  Once it's fixed we can use only protojure."
  [details]
  (let [d-bytes ^bytes (protojure/->pb details)
        cert2 (Cert$RawNebulaCertificate/parseFrom d-bytes)
        d-bytes2 (.toByteArray cert2)]
    d-bytes2))

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

(defn curve-str-kw
  "Return a keyword from curve str or nil."
  [curve]
  (case curve
    ("25519" "X25519" "Curve25519" "CURVE25519") :X25519
    "P256" :P256
    nil))

^:rct/test
(comment

  (map curve-str-kw ["25519" "X25519" "Curve25519" "CURVE25519" "P256" "Invalid"])
  ;; => (:X25519 :X25519 :X25519 :X25519 :P256 nil)

  )

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

(defmethod keygen :P256
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

(defmethod write-private :X25519
  [key-pair file & opts]
  (let [key-bytes (:private-key key-pair)
        banner (:X25519PrivateKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

(defmulti write-public
  "Given a keypair map, write public key to file"
  (fn [key-pair _file & _opts] (:key-type key-pair)))

(defmethod write-public :X25519
  [key-pair file & {:keys [file-mode] :as _opts}]
  (let [key-bytes (:public-key key-pair)
        banner (:X25519PublicKeyBanner cert-banners)
        pem (PemObject. banner key-bytes)]
    (write-pem! pem file)))

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
        message (cert-details->bytes raw-details)
        verifier (Ed25519Signer.)]
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature)))

(defn verify-signature-ed25519
  "Verify crypto signature.
   Return true if cert signature is valid, false either."
  [user-cert pub-key-bytes]
  (let [pub-key-params (Ed25519PublicKeyParameters. pub-key-bytes 0)
        signature (get-in user-cert [:Signature])
        raw-details (get-in user-cert [:Details])
        message (cert-details->bytes raw-details)
        verifier (Ed25519Signer.)]
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature)))

(defn check-signature
  "Check if a certificate is signed with the provided public key"
  ;; TODO: Implement as multimethod ?
  [cert pub-key]
  (let [curve (get-in cert [:Details :Curve])]
    (case curve
      "CURVE25519"
      (verify-signature-ed25519 cert pub-key)
      "P256"
      (throw (UnsupportedOperationException. "Not implemented"))
      :default  false)))

(defn marshal*
  "Convert RawNebulaCertificate to bytes.
  Include only :Details and :Signature "
  [cert]
  (let [c (select-keys cert [:Details :Signature])]
    (cert->bytes c)))

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

(defn expired?
  "Return true if given time is between not-before and not-after"
  [^Instant not-before ^Instant not-after ^Instant time]
  (and
   (-> time (.isBefore not-after))
   (-> time (.isAfter not-before))))

(defn expired-cert?
  [cert ^Instant time]
  (let [details (:Details cert)
        {:keys [NotBefore NotAfter]} details
        not-before (unix-timestamp->instant NotBefore)
        not-after (unix-timestamp->instant NotAfter)]
    (expired? not-before not-after time)))

^:rct/test
(comment

  (def base (Instant/now))
  (def before (.minusSeconds base 100))
  (def after (.plusSeconds base 100))

  (expired? before after base) ;; => true
  (expired? base before after) ;; => false
  (expired? after before base) ;; => false
  (expired? after base before) ;; => false
  )

(defn ip-str->ipv4
  "Helper to parse a string IP to ^IPv4Address.
   IPV4 only because nebula uses ipv4 for certs."
  ^IPv4Address [ip-str]
  (let [ip (IPAddressString. ip-str)
        ip (.toAddress ip IPAddress$IPVersion/IPV4)]
    ip))

^:rct/test
(comment

  (instance? IPv4Address (ip-str->ipv4 "10.0.0.1/24"))
  ;; => true

  (try
    (ip-str->ipv4 "10.0.0.a/24")
    (catch Exception e
      (ex-message e)))
  ;; => "10.0.0.a/24 IP Address error: invalid decimal digit"

  )
;; => nil


(defn contains-ip?
  "Check if subnet-ip contains ip.
   Use (contains-ip? ip) to create a predicate.
   The predicate accepts a subnet-ip and will check if the IP is in the subnet.
   You can also call with (partial contains-ip? subnet-ip)
   to make a predicate that accepts ip's and checks if they are inside the subnet-ip."
  ([^IPv4Address ip]
   (fn [^IPv4Address subnet-ip]
     (contains-ip? subnet-ip ip)))
  ([^IPv4Address subnet-ip ^IPv4Address ip]
   (if (or (not subnet-ip)
           (not ip))
     false
     (.contains subnet-ip ip))))

^:rct/test
(comment

  (contains-ip? (ip-str->ipv4 "10.10.0.1/16")
                (ip-str->ipv4 "10.10.0.1/24"))
  ;; => true

  (contains-ip? nil nil)
  ;; => false
  (contains-ip? nil (ip-str->ipv4 "10.10.0.1/16"))
  ;; => false
  (contains-ip? (ip-str->ipv4 "10.10.0.1/16") nil)
  ;; => false

  )

(defn net-match?
  "Check if cert-ip is in the list of provided CA IPs.
   All IP's should be ^IPv4Address ."
  [^IPv4Address cert-ip root-ips]
  (some? (some (contains-ip? cert-ip) root-ips)))

^:rct/test
(comment

  (def ips [(ip-str->ipv4 "10.10.0.0/16")
            (ip-str->ipv4 "10.11.0.0/24")])

  (net-match? (ip-str->ipv4 "10.10.1.0/16") ips)
  ;; => true

  (net-match? (ip-str->ipv4 "192.10.1.0/16") ips)
  ;; => false

  (net-match? (ip-str->ipv4 "10.10.1.0/24")
              [(ip-str->ipv4 "10.11.1.0/16")])
  ;; => false

  )


(defn check-root-constrains
  "Throw an error if cert violates constraints
   set by the CA that signed it: ips, groups, subnets, etc"
  [cert signer]
  (let [signer-not-after (get-in signer [:Details :NotAfter])
        signer-not-after ^Instant (unix-timestamp->instant signer-not-after)
        cert-not-after (get-in cert [:Details :NotAfter])
        cert-not-after ^Instant (unix-timestamp->instant cert-not-after)
        valid-after-signer? (-> cert-not-after (.isAfter signer-not-after))]
    ;; Make sure cert was not valid before signer
    (when valid-after-signer?
      (throw (ex-info "Certificate expires after signing certificate"
                      {:cert cert :ca signer}))))
  (let [signer-not-before (get-in signer [:Details :NotBefore])
        signer-not-before ^Instant (unix-timestamp->instant signer-not-before)
        cert-not-before (get-in cert [:Details :NotBefore])
        cert-not-before ^Instant (unix-timestamp->instant cert-not-before)
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
      (let [signer-ips (int-pairs->ipv4 signer-ips)
            ips (get-in cert [:Details :Ips])
            ips (int-pairs->ipv4 ips)
            matches (map #(net-match? % signer-ips) ips)
            ip-matches? (some true? matches)]
        (when-not ip-matches?
          (throw (ex-info "Certificate contained an ip assignment outside the limitations of the signing ca"
                          {:ips (map str ips)
                           :signer-ips (map str signer-ips)}))))))
  (let [signer-subnets (get-in signer [:Details :Subnets])]
  ;; If the signer has a limited set of subnet ranges to issue from,
  ;; make sure the cert only contains a subset
    (when (< 0 signer-subnets)
      (let [signer-subnets (int-pairs->ipv4 signer-subnets)
            subnets (get-in cert [:Details :Subnets])
            subnets (int-pairs->ipv4 subnets)
            matches (map #(net-match? % signer-subnets) subnets)
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
  (cert/pb->RawNebulaCertificate (.getContent pem)))

(defn verify-cert-files!
  "Verify a certificate is valid and issued by a specific CA.
  The CA file can contain multiple certs."
  [ca-cert-file user-cert-file]
  (when (str/blank? ca-cert-file)
    (throw (ex-info "CA cert file path is invalid"
                    {:path ca-cert-file})))
  (when (str/blank? user-cert-file)
    (throw (ex-info "User cert path is invalid"
                    {:path user-cert-file})))
  (let [user-pem (read-pem! user-cert-file)
        ca-cert-pems (read-pems! ca-cert-file)
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

  (mg/generate #"^x-\w*"))

(defn java-instant->iso-str
  "Format a java ^Instant to ISO DateTime"
  [^Instant instant]
  (let [d (OffsetDateTime/ofInstant instant (ZoneOffset/systemDefault))]
    (.format d DateTimeFormatter/ISO_OFFSET_DATE_TIME)))

(defn cert-fingerprint
  "Compute sha256 fingerprint as hex string."
  [raw-cert]
  (sha256sum+hex (cert->bytes raw-cert)))

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
        ips (into [] (map str (int-pairs->ipv4 Ips)))
        subnets (into [] (map str (int-pairs->ipv4 Subnets)))
        not-after (unix-timestamp->instant NotAfter)
        not-after (java-instant->iso-str not-after)
        not-before (unix-timestamp->instant NotBefore)
        not-before (java-instant->iso-str not-before)
        curve (str/upper-case (name curve))
        Issuer (format-hex Issuer)
        PublicKey (format-hex PublicKey)
        Signature (format-hex Signature)
        d {:Name Name
           :Curve curve
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
                  Issuer PublicKey Curve]} Details]
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
           "\t\tCurve: " Curve " \n"
           "\t}\n"
           "\tFingerprint: " Fingerprint "\n"
           "\tSignature: " Signature "\n"
           "}"))))

(defn print-cert-cli
  "CLI command - print details from a certificate."
  [cert-path & {:keys [json out-qr] :as opts}]
  (let [cert-pem (read-pem! cert-path)
        cert (pem->RawNebulaCertificate cert-pem)
        fingerpint (cert-fingerprint cert)
        c (RawNebulaCertificate->NebulaCertificate cert)
        c (assoc c :Fingerprint fingerpint)]
    (if json
      (j/write-value-as-string c cert-json-mapper)
      (cert-str c))))

(comment

  (def cert (pem->RawNebulaCertificate
             (read-pem! "sample-certs/sample-ca01.crt")))
  cert
  (RawNebulaCertificate->NebulaCertificate cert)

  )

(defn keygen-cli
  "CLI command - generate nebula keys."
  [curve out-key out-pub & _opts]
  (let [curve (curve-str-kw curve)
        key-pair (keygen {:key-type curve})]
    (write-private key-pair out-key)
    (write-public key-pair out-pub)))

(comment

  (keygen-cli "25519" "25519.key" "25519.pub")

  )