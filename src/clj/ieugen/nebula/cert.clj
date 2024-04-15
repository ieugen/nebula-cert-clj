(ns ieugen.nebula.cert
  "Port of nebula cert.go"
  (:require [clojure.set :as cset]
            [ieugen.nebula.crypto :as crypto]
            [ieugen.nebula.net :as net]
            [ieugen.nebula.time :as t]
            [protojure.protobuf :as protojure])
  (:import (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (java.time Instant)))


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

