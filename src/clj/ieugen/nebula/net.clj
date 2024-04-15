(ns ieugen.nebula.net
  "Network related functions"
  (:require [failjure.core :as f])
  (:import (inet.ipaddr IPAddress$IPVersion IPAddressString IPAddressStringParameters$Builder)
           (inet.ipaddr.ipv4 IPv4Address)))


(def ip-address-string-params
  (-> (IPAddressStringParameters$Builder.)
    (.allowEmpty false)
    (.setEmptyAsLoopback false)
    (.toParams)))

(defprotocol IPAddressProtocol
  (is-ipv4? [this])
  (is-ipv6? [this])

  (ipv4-int-value [this] "Return the int value of the IP as a signed integer.")
  (network-int-value [this] "Return the int value of the IP as a signed integer.")
  (network-prefix-length [this] "Return the network prefix length")
  (has-network-prefix [this] "Return true if IP address has a CIDR prefix"))

(extend-type IPv4Address
  IPAddressProtocol
  (is-ipv4? [this] (.isIPv4 this))
  (is-ipv6? [this] (.isIPv6 this))
  (ipv4-int-value [this] (-> this .intValue))
  (network-int-value [this] (-> this .getNetworkMask .intValue))
  (network-prefix-length [this] (.getNetworkPrefixLength this))
  (has-network-prefix [this] (some? (.getNetworkPrefixLength this))))

(extend-type IPAddressString
  IPAddressProtocol
  (is-ipv4? [this] (.isIPv4 this))
  (is-ipv6? [this] (.isIPv6 this))
  ;; (ipv4-int-value [this] (-> this .getAddress .intValue))
  ;; (network-int-value [this] (-> this .getAddress .getNetworkMask .intValue))
  (network-prefix-length [this] (.getNetworkPrefixLength this))
  (has-network-prefix [this] (some? (.getNetworkPrefixLength this))))

(defn address->ints
  "Return a sequence of IP and Network CIDR as int values"
  [ipv4]
  (when ipv4
    [(ipv4-int-value ipv4) (network-int-value ipv4)]))

(defn ip-bit-mask->cidr-bits
  "Given a bit mask: 11111111111111111111111100000000
   convert it to cidr: 24.
   Throws exception if int has discontiguos 1's and
   if CIDR is outside 0-32 bits"
  (^Integer [cidr]
   (let [leading-ones (int (- 32 (Integer/numberOfTrailingZeros cidr)))
         bit-count (Integer/bitCount cidr)
         same-bit-count? (= bit-count leading-ones)]
     ;; Network masks need to ahve contiguos number of 1's followed by 0's
     ;; https://datatracker.ietf.org/doc/html/rfc1519#section-4.2
     (when-not same-bit-count?
       (throw (ex-info (str "Integer value is not a network mask: "
                            (Integer/toBinaryString cidr)) {:cidr cidr})))
     (when (or (< leading-ones 0)
               (> leading-ones 32))
       (throw (ex-info (str "Integer valus is outside normal CIDR range "
                            leading-ones) {:cidr cidr
                                           :bit-count bit-count})))
     leading-ones)))

^:rct/test
(comment

  (try
    (ip-bit-mask->cidr-bits -3)
    (catch Exception e
      (ex-message e)))
  ;; => "Integer value is not a network mask: 11111111111111111111111111111101"

  (ip-bit-mask->cidr-bits -256)  ;; => 24
  (ip-bit-mask->cidr-bits -1)  ;; => 32
  (ip-bit-mask->cidr-bits 0)
  ;; => 0
  )

(defn ints->ipv4
  "Convert a pair of ints from nebula storage to an IPv4Address."
  (^IPv4Address [^Integer ip ^Integer cidr]
   (let [net-prefix (ip-bit-mask->cidr-bits cidr)]
     (IPv4Address. ip net-prefix))))

(defn int-pairs->ipv4
  "Convert a sequence of nebula IP/netmask paris to
   a sequence of ^IPv4Address"
  [ips+netmasks]
  (when (odd? (count ips+netmasks))
    (throw (ex-info (str "Ips should contain an even number of values "
                         (count ips+netmasks))
                    {:ips ips+netmasks})))
  (for [[ip mask] (partition 2 (map int ips+netmasks))]
    (ints->ipv4 ip mask)))

^:rct/test
(comment

  (map str (int-pairs->ipv4 nil))
  ;; => ()

  (map str (int-pairs->ipv4 []))
  ;; => ()

  ;; (map str (int-pairs->ipv4 [167772161]))
  ;; => Execution error (ExceptionInfo) at ieugen.nebula.net/int-pairs->ipv4 (net.clj:89).
  ;;    Ips should contain an even number of values 1

  (map str (int-pairs->ipv4 [0 -256 1 -256 2 -256]))
  ;; => ("0.0.0.0/24" "0.0.0.1/24" "0.0.0.2/24")

  (map str (int-pairs->ipv4 [167772161 -256 -1062731187 -256 -1062733187 -1024]))
  ;; => ("10.0.0.1/24" "192.168.2.77/24" "192.167.250.125/22")

  (address->ints nil)
  ;; => nil

  (address->ints (parse-ipv4 "127.0.0.1/16"))
  ;; => [2130706433 -65536]

  (address->ints (parse-ipv4 "127.0.0.1/32"))
  ;; => [2130706433 -1]

  (address->ints (parse-ipv4 "10.0.0.1/24"))
  ;; => [167772161 -256]

  (address->ints (parse-ipv4 "192.167.250.125/22"))
  ;; => [-1062733187 -1024]

  )


(defn parse-ipv4
  "Helper to parse a string IP to ^IPv4Address.
   IPV4 only because nebula uses ipv4 for certs.
   Return an ^IPv4Address in case of success.
   Return a failjure.core.Failure otherwise
   "
  ^IPv4Address [ip-str]
  (f/try-all [ip (IPAddressString. ip-str ip-address-string-params)
              _ip (when-not (is-ipv4? ip)
                    (f/fail "%s IP address error: IP is not IPv4" ip-str))
              ip (.toAddress ip IPAddress$IPVersion/IPV4)]
             ip
             (f/when-failed [e]
                            (f/fail (f/message e)))))

^:rct/test
(comment

  (parse-ipv4 nil)
  ;; => #failjure.core.Failure{:message "null IP address error: IP is not IPv4"}

  (parse-ipv4 "")
  ;; => #failjure.core.Failure{:message " IP address error: IP is not IPv4"}

  (instance? IPv4Address (parse-ipv4 "10.0.0.1/24"))
  ;; => true

  (str (parse-ipv4 "10.0.0.1/24"))
  ;; => "10.0.0.1/24"

  (parse-ipv4 "10.0.0.a/24")
  ;; => #failjure.core.Failure{:message "10.0.0.a/24 IP address error: IP is not IPv4"}

  (parse-ipv4 "2001:db8::2:1")
  ;; => #failjure.core.Failure{:message "2001:db8::2:1 IP address error: IP is not IPv4"}

  )

(defn parse-ipv4-cidr
  [cidr-str]
  (f/try-all [subnet (parse-ipv4 cidr-str)
              _subnet (when-not (has-network-prefix subnet)
                        (f/fail "Not a network address: %s" cidr-str))]
             subnet))

^:rct/test
(comment

  (parse-ipv4-cidr nil)
  ;; => #failjure.core.Failure{:message "null IP address error: IP is not IPv4"}

  (parse-ipv4-cidr "")
  ;; => #failjure.core.Failure{:message " IP address error: IP is not IPv4"}

  (parse-ipv4-cidr "192.168.0.0")
  ;; => #failjure.core.Failure{:message "Not a network address: 192.168.0.0"}

  (str (parse-ipv4-cidr "192.168.0.0/24"))
  ;; => "192.168.0.0/24"

  )

(defn addresses->ints
  [ips]
  (when ips
    (-> (map address->ints ips) flatten)))

^:rct/test
(comment

  (addresses->ints nil)
  ;; => nil

  (addresses->ints [])
  ;; => ()

  (->> ["192.167.250.125/22" "127.0.0.1/16" "127.0.0.1/32"]
       (map parse-ipv4)
       addresses->ints)
  ;; => (-1062733187 -1024 2130706433 -65536 2130706433 -1)


  )


(defn contains-ip?
  "Check if subnet-ip contains ip.
   Use (contains-ip? ip) to create a predicate.
   The predicate accepts a subnet-ip and will check if the IP is in the subnet.
   You can also call with (partial contains-ip? subnet-ip)
   to make a predicate that accepts ip's and checks if they are inside the subnet-ip."
  ([^IPv4Address ip]
   (fn [^IPv4Address subnet-ip]
     (contains-ip? subnet-ip ip)))
  ([^IPv4Address subnet-ip ^IPv4Address ip]
   (if (or (not subnet-ip)
           (not ip))
     false
     (.contains subnet-ip ip))))

^:rct/test
(comment

  (contains-ip? (parse-ipv4 "10.10.0.1/16")
                (parse-ipv4 "10.10.0.1/24"))
  ;; => true

  (contains-ip? nil nil)
  ;; => false
  (contains-ip? nil (parse-ipv4 "10.10.0.1/16"))
  ;; => false
  (contains-ip? (parse-ipv4 "10.10.0.1/16") nil)
  ;; => false
  )

(defn net-match?
  "Check if cert-ip is in the list of provided CA IPs.
   All IP's should be ^IPv4Address ."
  [^IPv4Address cert-ip root-ips]
  (some? (some (contains-ip? cert-ip) root-ips)))

^:rct/test
(comment

  (def ips [(parse-ipv4 "10.10.0.0/16")
            (parse-ipv4 "10.11.0.0/24")])

  (net-match? (parse-ipv4 "10.10.1.0/16") ips)
  ;; => true

  (net-match? (parse-ipv4 "192.10.1.0/16") ips)
  ;; => false

  (net-match? (parse-ipv4 "10.10.1.0/24")
              [(parse-ipv4 "10.11.1.0/16")])
  ;; => false
  )

