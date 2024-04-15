(ns ieugen.nebula.crypto
  (:import (java.nio.charset Charset StandardCharsets)
           (java.security MessageDigest)
           (java.util HexFormat)
           (org.bouncycastle.jce ECNamedCurveTable)))

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