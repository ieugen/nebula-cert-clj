(ns ieugen.nebula.crypto-test
  (:require [clojure.test :as test :refer [deftest testing is ]]
            [failjure.core :as f]
            [ieugen.nebula.pem :as pem]
            [ieugen.nebula.crypto :as sut]
            [ieugen.nebula.cert :as cert])
  (:import (java.util Arrays)))


(deftest crypto-sign-tests

  ;; Sign a certificate using a nebula CA
  ;; Sign the same certificate using nebula-clj
  ;; Compare signatures
  (testing "Sign certificate with ed25519"
    (f/try-all  [ca-key (pem/read-pem-type! "NEBULA ED25519 PRIVATE KEY" "sample-certs/sample-ca01.key")
                 cert-bytes (pem/read-pem-type! "NEBULA CERTIFICATE" "sample-certs/sample-cert-01.crt")
                 raw-cert (cert/bytes-RawCertificate cert-bytes)
                 raw-signature (:Signature raw-cert)
                 raw-details (:Details raw-cert)
                 curve (:curve raw-details)
                 raw-detail-bytes (cert/marshal-raw-cert-details raw-details)
                 signature (sut/sign curve ca-key raw-detail-bytes)]
                (is (Arrays/equals raw-signature signature))
                (f/when-failed
                 [e]
                 (is false (f/message e))))))



(comment
  (pem/read-pem-type! "NEBULA ED25519 PRIVATE KEY" "sample-certs/sample-ca01.key")
  (->
   (pem/read-pem-type! "NEBULA CERTIFICATE" "sample-certs/sample-cert-01.crt")
   (cert/bytes-RawCertificate))

  )