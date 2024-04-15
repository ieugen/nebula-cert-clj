(ns ieugen.nebula.crypto
  (:import (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest)
           (java.util HexFormat)))

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