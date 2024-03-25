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
  (not-implemented))

(defn verify
  "Verifies a certificate isn't expired and was signed by a trusted authority."
  [flags]
  (let [{:keys [ca crt]} flags]
    (certs/verify-cert-files! ca crt)))

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
                            "pring" #'my-print
                            "verify" {:command #'verify
                                      :flags ["--ca FILE"
                                              "Required: path to a filecontaining one or more ca certificates"
                                              "--crt FILE"
                                              "Required: path to a file containing a single certificate"]}]}))
