(ns ieugen.nebula.cli
  "A port for nebula-cert command line applcation to clojure."
  (:require [lambdaisland.cli :as cli]
            [clojure.pprint :as pprint]
            [ieugen.nebula.certs :as certs]))


(defn cli-top-level
  "nebula-certs-clj - A port of nebula-certs to clojure."
  [flags]
  (pprint/pprint flags))

(defn not-implemented
  ([]
   (not-implemented nil))
  ([flags]
   (println "Not implemented yet" flags)))
(defn ca
  "Create a self signed certificate authority"
  [flags]
  (not-implemented))

(defn keygen
  "Create a public/private key pair.
   The public key can be signed by a nebula CA"
  [flags]
  (not-implemented))

(defn sign
  "Create and sign a certificate."
  [flags]
  (not-implemented))

(defn my-print
  "Print details about a certificate"
  [flags]
  (let [{:keys [path]} flags
        data (certs/print-cert
              path
              (select-keys flags [:json :out-qr]))]
    (println data)))

(defn verify
  "Verifies a certificate isn't expired and was signed by a trusted authority."
  [flags]
  (let [{:keys [ca crt]} flags]
    (if (certs/verify-cert-files! ca crt)
      true
      (do
        (println "Certs don't match")
        (System/exit -1)))))

(defn -main
  "Main CLI entry point.
   Run with clojure -M -m ieugen.nebula.cli"
  [& args]
  (cli/dispatch {:name "nebula-cert-clj"
                 :doc "A port of nebula-certs to clojure."
                 ;;  :command #'cli-top-level
                 :strict? true
                 :flags ["-V, -version" "Prints the version"
                         "-h, --help" "Prints this help message"]
                 :commands ["ca" #'ca
                            "keygen" #'keygen
                            "sign" #'sign
                            "print" {:command #'my-print
                                     :flags ["--json" "Optional: outputs certificates in json format"
                                             "--out-qr STR" "NOT Implemented: output a QR code image (png) of the certificate"
                                             "--path FILE" "Required: path to certificate"]}
                            "verify" {:command #'verify
                                      :flags ["--ca FILE"
                                              "Required: path to a filecontaining one or more ca certificates"
                                              "--crt FILE"
                                              "Required: path to a file containing a single certificate"]}]}))
