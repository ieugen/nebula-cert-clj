(ns ieugen.nebula.pem
  "Protocol and utilities for working with PEM files and data."
  (:require [clojure.java.io :as io])
  (:import
   (org.bouncycastle.util.io.pem PemObject PemReader PemWriter)))

;; TODO: @ieugen: Use byte array or InutStream as

(defprotocol PemProtocol
  "Protocol to deal with PEM files - Privacy enhanced email.
   See https://www.rfc-editor.org/rfc/rfc1422"
  ;; https://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file
  (get-type ^String [this] "Get the type of PEM structure")
  (get-headers [this] "Get PEM headers as sequence")
  (get-content ^bytes [this] "Get the PEM contents as a byte array"))

(extend-type PemObject
  PemProtocol
  (get-type [this] (.getType this))
  (get-headers [this] (.getHeaders this))
  (get-content [this] (.getContent this)))


(defn read-pem!
  "Read pem from file, url, etc.
   To pass String, wrap in InputStream."
  (^PemObject [pem]
   (let [pr (PemReader. (io/reader pem))]
     (.readPemObject pr))))

(defn read-pems!
  "Read all certs (pem objects) from a PEM file, url, etc.
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


(defmulti unmarshal
  "Unmarshal content from a type implementing ^PemProtocol"
  (fn [pem] (get-type pem)))