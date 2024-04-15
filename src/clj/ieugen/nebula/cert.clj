(ns ieugen.nebula.cert
  "Port of nebula cert.go"
  (:require [clojure.set :as cset]
            [clojure.string :as str]
            [failjure.core :as f]
            [ieugen.nebula.crypto :as crypto]
            [ieugen.nebula.generated.cert :as gcert]
            [ieugen.nebula.net :as net]
            [ieugen.nebula.pem :as pem]
            [ieugen.nebula.time :as t]
            [malli.core :as m]
            [malli.error :as me]
            [protojure.protobuf :as protojure])
  (:import (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (java.time Instant Duration)
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