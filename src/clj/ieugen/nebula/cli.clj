(ns ieugen.nebula.cli
  "A port for nebula-cert command line applcation to clojure."
  (:require [ieugen.nebula.certs :as certs]
            [lambdaisland.cli :as cli]))

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
   The public key can be signed by a nebula CA with `sign`"
  [flags]
  (let [{:keys [curve out-key out-pub]} flags]
    (certs/keygen-cli curve out-key out-pub)))

(defn sign
  "Create and sign a certificate."
  [flags]
  (not-implemented))

(defn my-print
  "Print details about a certificate"
  [flags]
  (let [{:keys [path]} flags
        data (certs/print-cert-cli
              path
              (select-keys flags [:json :out-qr]))]
    (println data)))

(defn verify
  "Verifies a certificate isn't expired and was signed by a trusted authority."
  [flags]
  (let [{:keys [ca crt]} flags]
    (if (certs/verify-cert-files! ca crt)
      (do
        (println "ok")
        true)
      (do
        (println "Certs don't match")
        (System/exit -1)))))

(defn -main
  "Main CLI entry point.
   Run with clojure -M -m ieugen.nebula.cli"
  [& args]
  (cli/dispatch
   {:name "nebula-cert-clj"
    :doc "A port of nebula-certs to clojure."
                 ;;  :command #'cli-top-level
    :strict? true
    :flags ["-V, -version" "Prints the version"
            "-h, --help" "Prints this help message"]
    :commands
    ["ca" {:command #'ca
           :flags
           ["--argon-iterations uint"
            {:doc "Optional: Argon2 iterations parameter used for encrypted private key passphrase"
             :default 1}
            "--argon-memory uint"
            {:doc "Optional: Argon2 memory parameter (in KiB) used for encrypted private key passphrase"
             :default 2097152}
            "--argon-paralelism uint"
            {:doc "Optional: Argon2 parallelism parameter used for encrypted private key passphrase"
             :default 4}
            "--curve string"
            {:doc "EdDSA/ECDSA Curve (25519, P256)"
             :default "25519"}
            "--duration DURATION"
            {:doc (str "Optional: amount of time the certificate should be valid for."
                       "Valid time units are seconds: 's', minutes: 'm', hours: 'h'")
             :default "8760h0m0s"}
            "--encrypt"
            "Optional: prompt for passphrase and write out-key in an encrypted format"
            "--groups string"
            {:doc (str "Optional: comma separated list of groups."
                       "This will limit which groups subordinate certs can use")}
            "--ips string"
            {:doc
             (str "Optional: comma separated list of ipv4 address and network in CIDR notation."
                  "This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses")}
            "--name string"
            "Required: name of the certificate authority"
            "--out-crt string"
            {:doc "Optional: path to write the certificate to"
             :default "ca.crt"}
            "--out-key string"
            {:doc "Optional: path to write the private key to"
             :default "ca.key"}
            "--out-qr string"
            "Optional: output a qr code image (png) of the certificate"
            "--subnets string"
            {:doc
             (str "Optional: comma separated list of ipv4 address and network "
                  "in CIDR notation. "
                  "This will limit which ipv4 addresses and "
                  "networks subordinate certs can use in subnets")}]}
     "keygen" {:command #'keygen
               :flags
               ["--curve String"
                {:doc "ECDH Curve (25519, P256) (default \"25519\")"
                 :default "25519"}
                "--out-key FILE"
                "Required*: path to write the private key to"
                "--out-pub FILE"
                "Required*: path to write the public key to"]}
     "sign" {:command #'sign
             :flags
             ["--ca-crt FILE"
              {:doc "Optional: Path to the signing CA cert"
               :default "ca.crt"}
              "--ca-key FILE"
              {:doc "Optional: Path to the signing CA key"
               :default "ca.key"}
              "--duration DURATION"
              {:doc
               (str "Optional: How long the cert should be valid for. "
                    "Default is 1s before the signing cert expires."
                    "Valid time units are seconds: 's', minutes: 'm' and hours: 'h'")}
              "--groups string"
              "Optional: comma separated list of groups."
              "--in-pub FILE"
              "Optional (if out-key not set): path to read a previously generated public key"
              "--ip string"
              "Required: ipv4 address and network in CIDR notation to assign the cert"
              "--name string"
              "Required: Name of the cert, usually a hostname"
              "--out-crt string"
              "Optional: Path to write the certificate to"
              "--out-key string"
              "Optional (if in-pub not set): Path to write the private key to"
              "--out-qr string"
              "Optional: Output a QR code image (png) of the certificate."
              "--subnets string"
              {:doc
               (str "Optional: comma separated list of ipv4 address and network in CIDR notation."
                    "Subnets tis cert can serve for.")}]}
     "print" {:command #'my-print
              :flags
              ["--json"
               "Optional: outputs certificates in json format"
               "--out-qr FILE"
               "NOT Implemented: output a QR code image (png) of the certificate"
               "--path FILE"
               "Required: path to certificate"]}
     "verify" {:command #'verify
               :flags
               ["--ca FILE"
                "Required: path to a filecontaining one or more ca certificates"
                "--crt FILE"
                "Required: path to a file containing a single certificate"]}]}))
