(ns ieugen.nebula.cert
  "Port of nebula cert.go"
  (:require [clojure.set :as cset]
            [clojure.string :as str]
            [ieugen.nebula.crypto :as crypto]
            [ieugen.nebula.generated.cert :as gcert]
            [ieugen.nebula.net :as net]
            [ieugen.nebula.pem :as pem]
            [ieugen.nebula.time :as t]
            [malli.core :as m]
            [malli.error :as me]
            [protojure.protobuf :as protojure])
  (:import (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (java.time Instant)
           (org.bouncycastle.util.io.pem PemObject)))

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

(defn marshal*
  "Convert RawNebulaCertificate to bytes.
  Include only :Details and :Signature "
  [cert]
  (let [c (select-keys cert [:Details :Signature])]
    (marshal-raw-cert c)))

(defn cert->hex-sha256sum
  [cert]
  (let [b (marshal* cert)
        sum256 (crypto/sha256sum+hex b)]
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

(defmethod pem/unmarshal "NEBULA CERTIFICATE"
  ([^PemObject pem]
   (let [raw-cert (Cert$RawNebulaCertificate/parseFrom (pem/get-content pem))
         raw-cert (valid-raw-nebula-certificate raw-cert)]
     raw-cert)))

(defmethod pem/unmarshal "NEBULA ED25519 PRIVATE KEY"
  ([^PemObject pem]
   (let [raw ()])))


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

(defn pem->RawNebulaCertificate
  "Parse a nebula cert from a ^PemObject"
  [^PemObject pem]
  (gcert/pb->RawNebulaCertificate (pem/get-content pem)))


(defn cert-fingerprint
  "Compute sha256 fingerprint as hex string."
  [raw-cert]
  (crypto/sha256sum+hex (marshal-raw-cert raw-cert)))

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
        not-after (t/java-instant->iso-str not-after)
        not-before (t/unix-timestamp->instant NotBefore)
        not-before (t/java-instant->iso-str not-before)
        curve (str/upper-case (name curve))
        Issuer (crypto/format-hex Issuer)
        PublicKey (crypto/format-hex PublicKey)
        Signature (crypto/format-hex Signature)
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