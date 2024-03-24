(ns ieugen.nebula.certs
  (:require [clojure.java.io :as io]
            [malli.core :as m]
            [malli.error :as me]
            [malli.generator :as mg]
            [ieugen.nebula.generated.cert :as cert]
            [protojure.protobuf :as protojure])
  (:import (com.google.protobuf ByteString)
           (inet.ipaddr.ipv4 IPv4Address)
           (java.time Instant)
           (java.util HexFormat)
           (ieugen.nebula.generated.cert Cert$RawNebulaCertificate Cert$RawNebulaCertificateDetails)
           (org.bouncycastle.crypto Signer)
           (org.bouncycastle.crypto.params Ed25519PrivateKeyParameters Ed25519PublicKeyParameters)
           (org.bouncycastle.crypto.signers Ed25519Signer)
           (org.bouncycastle.util.io.pem PemObject PemReader PemWriter)))

(set! *warn-on-reflection* true)

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

(defmulti unmarshal (fn [^PemObject pem] (.getType pem)))

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

(defmethod unmarshal "NEBULA CERTIFICATE"
  ([^PemObject pem]
   (let [raw-cert (Cert$RawNebulaCertificate/parseFrom (.getContent pem))
         raw-cert (valid-raw-nebula-certificate raw-cert)]
     raw-cert)))

(defmethod unmarshal "NEBULA ED25519 PRIVATE KEY"
  ([^PemObject pem]
   (let [raw ()])))

(defn file->bytes [file]
  (with-open [xin (io/input-stream file)
              xout (java.io.ByteArrayOutputStream.)]
    (io/copy xin xout)
    (.toByteArray xout)))


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

  (def hex (HexFormat/of))

  (def ieugen-bytes (cert/pb->RawNebulaCertificateDetails (io/input-stream "ieugen.bytes")))

  (.formatHex hex (:PublicKey ieugen-bytes))

  (.formatHex hex (:PublicKey (:Details ieugen-crt)))

  (def rnc (Cert$RawNebulaCertificate/parseFrom (.getContent (read-pem! "ieugen.crt"))))

  (->> rnc
       (.getDetails)
       (.toByteArray)
       (.formatHex hex))

  (def a (file->bytes "ieugen.bytes"))
  (.formatHex hex a)
  (def arr (protojure/->pb (:Details ieugen-crt)))
  (.formatHex hex arr)

  (cert/pb->RawNebulaCertificateDetails arr)

  (.formatHex hex (protojure/->pb (cert/pb->RawNebulaCertificateDetails a)))


  ;; Ed25519Signer
  ;; https://github.com/slackhq/nebula/blob/master/cert/cert.go#L807
  (let [ieugen-crt (cert/pb->RawNebulaCertificate (.getContent (read-pem! "ieugen.crt")))
        dre-ca-crt (cert/pb->RawNebulaCertificate (.getContent (read-pem! "dre-ca.crt")))
        pub-key-params (Ed25519PublicKeyParameters. (get-in dre-ca-crt [:Details :PublicKey]) 0)
        signature (get-in ieugen-crt [:Signature])
        verifier (Ed25519Signer.)
        message (file->bytes "ieugen.bytes")]
    (println ieugen-crt "\n")
    (println dre-ca-crt "\n")
    (.init verifier false pub-key-params)
    (.update verifier message 0 (count message))
    (.verifySignature verifier signature))



  ieugen-crt
  (keys (:Details ieugen-crt))

  (.formatHex hex (:Issuer (:Details ieugen-crt)))


  (unix-timestamp->instant (get-in ieugen-crt [:Details :NotAfter]))

  (cert/pb->RawNebulaCertificate (.getContent ca-crt))

  (unmarshal ca-crt)

  (bean ca-crt)

  (def rc (valid-raw-nebula-certificate
           (cert/pb->RawNebulaCertificate (.getContent ca-crt))))

  (-> rc
      :Details
      :Issuer
      (String.))

  (-> rc
      :Details
      :NotBefore
      unix-timestamp->instant)

  (-> rc
      :Details
      :NotAfter
      unix-timestamp->instant)

  (-> rc
      :Signature
      String.)

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