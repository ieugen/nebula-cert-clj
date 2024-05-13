(ns ieugen.nebula.cli
  "A port for nebula-cert command line applcation to clojure."
  (:require [clojure.string :as str]
            [failjure.core :as f]
            [ieugen.nebula.cert :as cert]
            [ieugen.nebula.core :as core]
            [ieugen.nebula.crypto :as crypto]
            [ieugen.nebula.net :as net]
            [ieugen.nebula.time :as time]
            [lambdaisland.cli :as cli]))


(defn cmd-ca
  "Create a self signed certificate authority"
  [flags]
  (f/try-all [{:keys [name out-key out-crt duration
                      groups ips subnets encrypt curve
                      argon-iterations argon-memory argon-paralelism]} flags
              name (if (str/blank? name)
                     (f/fail "CA name is required")
                     name)
              out-key (if (str/blank? out-key)
                        (f/fail "out-key is required")
                        out-key)
              out-crt (if (str/blank? out-crt)
                        (f/fail "out-crt is required")
                        out-crt)
              duration (if (time/pos-duration? duration)
                         duration
                         (f/fail "a positive duration is required %s" duration))
              passphrase (when encrypt
                           (.readPassword (System/console) "Enter pasword: ", (object-array [])))
              groups (cert/parse-groups groups)
              ips (net/parse-ips-or-subnets ips)
              subnets (net/parse-ips-or-subnets subnets)
              key-pair (crypto/keygen {:key-type :curve25519})
              {:keys [private-key public-key]} key-pair
              now (time/now)
              not-after (time/compute-cert-not-after now duration)
              nc {:Details {:Name name
                            :Groups groups
                            :Ips ips
                            :Subnets subnets
                            :NotBefore now
                            :NotAfter not-after
                            :PublicKey public-key
                            :Issuer ""
                            :curve :curve25519
                            :IsCA true}}
              ;; TODO: check files exist
              nc (core/sign-cert nc :curve25519 private-key)
              ;; TODO: encrypt key if asked
              b (if encrypt
                  (let [pw (String. passphrase)
                        params (crypto/make-argon-params argon-iterations argon-memory argon-paralelism)]
                    (crypto/aes-256-encrypt pw params private-key))
                  private-key)
              ;; TODO: write private key
              ;; TODO: write certificate
              ;; TODO: write qr code
              ]
             (println name out-key out-crt duration groups ips subnets (String. passphrase)
                      nc)
             (f/when-failed [e]
                            (println (f/message e) e))))
(comment

  (cmd-ca {:name ""}))


(defn cmd-keygen
  "Create a public/private key pair.
   The public key can be signed by a nebula CA with `sign`"
  [flags]
  (let [{:keys [curve out-key out-pub]} flags]
    (core/cli-keygen curve out-key out-pub)))

(defn cmd-sign
  "Create and sign a certificate."
  [flags]
  (let [{:keys [ca-crt ca-key name ip out-qr]} flags
        opts {:flags flags}]
    (when out-qr
      (println "QR generation is not implemented"))
    (core/cli-sign ca-crt ca-key name ip opts)))

(defn cmd-print
  "Print details about a certificate"
  [flags]
  (let [{:keys [path out-qr]} flags
        data (core/cli-print-cert
              path
              (select-keys flags [:json :out-qr]))]
    (when out-qr
      (println "QR generation is not implemented."))
    (println data)))

(defn cmd-verify
  "Verifies a certificate isn't expired and was signed by a trusted authority."
  [flags]
  (let [{:keys [ca crt]} flags]
    ;;TODO: USe certs/verify
    (if (core/verify-cert-files! ca crt)
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
    ["ca" {:command #'cmd-ca
           :flags
           ["--argon-iterations UINT" {:doc "Optional: Argon2 iterations parameter used for encrypted private key passphrase"
                                       :default 1}
            "--argon-memory UINT" {:doc "Optional: Argon2 memory parameter (in KiB) used for encrypted private key passphrase"
                                   :default 2097152}
            "--argon-paralelism UINT" {:doc "Optional: Argon2 parallelism parameter used for encrypted private key passphrase"
                                       :default 4}
            "--curve STRING" {:doc "EdDSA/ECDSA Curve (25519, P256)"
                              :default "25519"}
            "--duration DURATION" {:doc (str "Optional: amount of time the certificate should be valid for."
                                             "Valid time units are seconds: 's', minutes: 'm', hours: 'h'")
                                   :default (time/parse-duration "8760h0m0s")
                                   :parse time/parse-duration}
            "--encrypt" "Optional: prompt for passphrase and write out-key in an encrypted format"
            "--groups STRING" {:doc (str "Optional: comma separated list of groups."
                                         "This will limit which groups subordinate certs can use")}
            "--ips STRING" {:doc
                            (str "Optional: comma separated list of ipv4 address and network in CIDR notation."
                                 "This will limit which ipv4 addresses and networks subordinate certs can use for ip addresses")}
            "--name STRING" "Required: name of the certificate authority"
            "--out-crt STRING" {:doc "Optional: path to write the certificate to"
                                :default "ca.crt"}
            "--out-key STRING" {:doc "Optional: path to write the private key to"
                                :default "ca.key"}
            "--out-qr STRING" "Optional: output a qr code image (png) of the certificate"
            "--subnets STRING" {:doc
                                (str "Optional: comma separated list of ipv4 address and network "
                                     "in CIDR notation. "
                                     "This will limit which ipv4 addresses and "
                                     "networks subordinate certs can use in subnets")}]}
     "keygen" {:command #'cmd-keygen
               :flags
               ["--curve STRING"
                {:doc "ECDH Curve (25519, P256) (default \"25519\")"
                 :default "25519"}
                "--out-key FILE"
                "Required*: path to write the private key to"
                "--out-pub FILE"
                "Required*: path to write the public key to"]}
     "sign" {:command #'cmd-sign
             :flags
             ["--ca-crt FILE" {:doc "Optional: Path to the signing CA cert"
                               :default "ca.crt"}
              "--ca-key FILE" {:doc "Optional: Path to the signing CA key"
                               :default "ca.key"}
              "--duration DURATION" {:doc
                                     (str "Optional: How long the cert should be valid for. "
                                          "Default is 1s before the signing cert expires."
                                          "Valid time units are seconds: 's', minutes: 'm' and hours: 'h'")
                                     :default (time/parse-duration "0s")
                                     :parse time/parse-duration}
              "--groups STRING" "Optional: comma separated list of groups."
              "--in-pub FILE" "Optional (if out-key not set): path to read a previously generated public key"
              "--ip STRING" "Required: ipv4 address and network in CIDR notation to assign the cert"
              "--name STRING" "Required: Name of the cert, usually a hostname"
              "--out-crt STRING" "Optional: Path to write the certificate to"
              "--out-key STRING" "Optional (if in-pub not set): Path to write the private key to"
              "--out-qr STRING" "Optional: Output a QR code image (png) of the certificate."
              "--subnets STRING" {:doc
                                  (str "Optional: comma separated list of ipv4 address and network in CIDR notation."
                                       "Subnets tis cert can serve for.")}]}
     "print" {:command #'cmd-print
              :flags
              ["--json"
               "Optional: outputs certificates in json format"
               "--out-qr FILE"
               "NOT Implemented: output a QR code image (png) of the certificate"
               "--path FILE"
               "Required: path to certificate"]}
     "verify" {:command #'cmd-verify
               :flags
               ["--ca FILE"
                "Required: path to a filecontaining one or more ca certificates"
                "--crt FILE"
                "Required: path to a file containing a single certificate"]}]}))
