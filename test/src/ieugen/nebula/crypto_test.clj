(ns ieugen.nebula.crypto-test
  (:require [babashka.fs :as fs]
            [clojure.test :as test :refer [deftest testing is]]
            [failjure.core :as f]
            [ieugen.nebula.pem :as pem]
            [ieugen.nebula.crypto :as sut]
            [ieugen.nebula.cert :as cert]
            [ieugen.nebula.generated.cert :as gcert])
  (:import (java.util Arrays)))


(deftest crypto-sign-tests

  ;; Sign a certificate using a nebula CA
  ;; Sign the same certificate using nebula-clj
  ;; Compare signatures
  (testing "Sign certificate with ed25519"
    (f/try-all  [ca-key (pem/read-pem-type! "NEBULA ED25519 PRIVATE KEY" "sample-certs/sample-ca01.key")
                 cert-bytes (pem/read-pem-type! "NEBULA CERTIFICATE" "sample-certs/sample-cert-01.crt")
                 raw-cert (cert/bytes->RawCertificate cert-bytes)
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
   (cert/bytes->RawCertificate)))



(deftest crypto-argon2-decrypt-tests

  (testing "split and join nonce and text"
    (let [nonce+cipher (fs/read-all-bytes "sample-certs/encrypted-ca/blob.bytes")
          nonce-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/nonce.bytes")
          cipher-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/ciphertext.bytes")
          [nonce  cipher] (sut/split-nonce-cipher-text nonce+cipher)
          new-blob (sut/join-nonce-cipher-text nonce-bytes cipher-bytes)]
      (is (Arrays/equals nonce nonce-bytes) "Nonce is not split correctly from blob")
      (is (Arrays/equals cipher cipher-bytes) "Cipher is not split correctly from blob")
      (is (Arrays/equals new-blob nonce+cipher) "Nonce and cipher are not joined to the same blob")))


  (testing "aes256 derive key algoritm"
    (let [passphrase-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/passphrase.bytes")
          key-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/key.bytes")
          rned (gcert/pb->RawNebulaEncryptedData
                (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                    "sample-certs/encrypted-ca/encrypted-ca.key"))
          params (get-in rned [:EncryptionMetadata :Argon2Parameters])
          result (sut/derive-key (String. passphrase-bytes "UTF-8") 32 params)
          result-hex (sut/bytes->hex result)]
      (is (= "2aed09c648fe20622e6a93fd0339ffb441d9f951390134f85192a0927b47ca12"
             (sut/bytes->hex key-bytes))
          "AWS encryption key has proepr value")
      (is (= "2aed09c648fe20622e6a93fd0339ffb441d9f951390134f85192a0927b47ca12"
             result-hex)
          "Derived key does not match")))


  ;; generate an encrypted CA cert using nebula-cert
  ;; read the encrypted key and decrypt it

  (testing "decrypt private key data that nebula encrypted"
    (let [passphrase "s3cret"
          rned (gcert/pb->RawNebulaEncryptedData
                (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                    "sample-certs/encrypted-ca/encrypted-ca.key"))
          cipher-text (get-in rned [:Ciphertext])
          params (get-in rned [:EncryptionMetadata :Argon2Parameters])
          expected-data (fs/read-all-bytes "sample-certs/encrypted-ca/encrypted-ca_raw_key.bytes")
          result (sut/aes-256-drecrypt passphrase params cipher-text)]

      (is (Arrays/equals expected-data result)
          "Decrypted data does not match expected data")))

  ;; encrypt the private key using the same key
  ;; compare it with the encrypted key file 
  (testing "encrypt private key data matches what nebula does"
    (let [passphrase "s3cret"
          rned (gcert/pb->RawNebulaEncryptedData
                (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                    "sample-certs/encrypted-ca/encrypted-ca.key"))
          expected-nonce+cipher (get-in rned [:Ciphertext])
          ;; we need to use the same nonce when encrypting to get the same encrypted data
          [nonce _cipher-txt] (sut/split-nonce-cipher-text expected-nonce+cipher)
          params (get-in rned [:EncryptionMetadata :Argon2Parameters])
          key-to-encrypt (fs/read-all-bytes "sample-certs/encrypted-ca/encrypted-ca_raw_key.bytes")
          result (sut/aes-256-encrypt passphrase params key-to-encrypt nonce)]
      (is (Arrays/equals result expected-nonce+cipher)
          "Encrypted data does not match expected data"))))

(comment

  (gcert/pb->RawNebulaEncryptedData
   (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                       "sample-certs/encrypted-ca/encrypted-ca.key"))
;; => {:EncryptionMetadata
;;     {:EncryptionAlgorithm "AES-256-GCM",
;;      :Argon2Parameters
;;      {:version 19,
;;       :memory 2097152,
;;       :parallelism 4,
;;       :iterations 1,
;;       :salt
;;       [-4, 44, -11, -89, -86, 122, 101, 3, -77, -5, 124, 106, 47, 89, 3, -94, 26, -29, -29, 63, -27, -125, -32, 3, 26,
;;        -123, -108, 29, 37, 41, 42, 25]}},
;;     :Ciphertext
;;     [-119, 39, -37, 63, -127, 70, -98, -85, -59, 68, 50, -65, -115, -85, -19, 5, 8, -68, 103, -73, -122, -124, 8, -71,
;;      -101, -45, -106, -77, -41, -85, 73, -42, -37, -77, -48, 32, -97, -114, 65, 95, 92, 6, 27, -14, -77, -30, 61, -58,
;;      -48, 112, ...]}

  (->
   (fs/read-all-bytes "sample-certs/encrypted-ca/passphrase.bytes")
   (String. "UTF-8"))
    ;; => "s3cret" 

  (def nonce (fs/read-all-bytes "sample-certs/encrypted-ca/nonce.bytes"))
  (sut/bytes->hex nonce)
  ;; => "8927db3f81469eabc54432bf"
  (count nonce)
  ;; => 12

  (def pwd-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/passphrase.bytes"))
  (sut/bytes->hex pwd-bytes)
  ;; => "733363726574"

  (count pwd-bytes)
  ;; => 6

  (def cipher-txt (fs/read-all-bytes "sample-certs/encrypted-ca/ciphertext.bytes"))
  (sut/bytes->hex cipher-txt)
  ;; => "8dabed0508bc67b7868408b99bd396b3d7ab49d6dbb3d0209f8e415f5c061bf2b3e23dc6d0706a5e9a15d5ae4db4baefb3979b5bf9bcf20e1312ab7fa5a39bc32990625c6d698a685bb0f0a606c3d772"
  (count cipher-txt)
  ;; => 80

  (def blob (fs/read-all-bytes "sample-certs/encrypted-ca/blob.bytes"))

  (sut/bytes->hex blob)
  ;; => "8927db3f81469eabc54432bf8dabed0508bc67b7868408b99bd396b3d7ab49d6dbb3d0209f8e415f5c061bf2b3e23dc6d0706a5e9a15d5ae4db4baefb3979b5bf9bcf20e1312ab7fa5a39bc32990625c6d698a685bb0f0a606c3d772"

  (count blob)
  ;; => 92 


  (def key-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/key.bytes"))
  (sut/bytes->hex key-bytes)
  ;; => "2aed09c648fe20622e6a93fd0339ffb441d9f951390134f85192a0927b47ca12"
  (count key-bytes)
  ;; => 32


  (let [passphrase-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/passphrase.bytes")
        pwd (String. passphrase-bytes "UTF-8")
        _ (println "PWD" pwd)
        key-bytes (fs/read-all-bytes "sample-certs/encrypted-ca/key.bytes")
        rncd (gcert/pb->RawNebulaEncryptedData
              (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                  "sample-certs/encrypted-ca/encrypted-ca.key"))
        params (get-in rncd [:EncryptionMetadata :Argon2Parameters])
        result (sut/derive-key pwd 32 params)]
    (println "Expecting" (sut/bytes->hex key-bytes))
    (sut/bytes->hex result))


  (let [passphrase "s3cret"
        rned (gcert/pb->RawNebulaEncryptedData
              (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                  "sample-certs/encrypted-ca/encrypted-ca.key"))
        cipher-text (get-in rned [:Ciphertext])
        params (get-in rned [:EncryptionMetadata :Argon2Parameters])
        expected-data (fs/read-all-bytes "sample-certs/encrypted-ca/encrypted-ca_raw_key.bytes")
        result (sut/aes-256-drecrypt passphrase params cipher-text)]
    (println "Expected" (sut/bytes->hex expected-data))
    (println "Result" (sut/bytes->hex result))
    (println "Results are" (Arrays/equals expected-data result)))

  (let [passphrase "s3cret"
        rned (gcert/pb->RawNebulaEncryptedData
              (pem/read-pem-type! "NEBULA ED25519 ENCRYPTED PRIVATE KEY"
                                  "sample-certs/encrypted-ca/encrypted-ca.key"))
        expected-nonce+cipher (get-in rned [:Ciphertext])
        ;; we need to use the same nonce when encrypting to get the same encrypted data
        [nonce _cipher-txt] (sut/split-nonce-cipher-text expected-nonce+cipher)
        params (get-in rned [:EncryptionMetadata :Argon2Parameters])
        key-to-encrypt (fs/read-all-bytes "sample-certs/encrypted-ca/encrypted-ca_raw_key.bytes") 
        result (sut/aes-256-encrypt passphrase params key-to-encrypt nonce)]
    (Arrays/equals result expected-nonce+cipher))


  )