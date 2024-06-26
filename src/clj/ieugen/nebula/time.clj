(ns ieugen.nebula.time
  (:require [failjure.core :as f])
  (:import (java.time Duration
                      Instant
                      OffsetDateTime ZoneOffset)
           (java.time.format DateTimeFormatter)))


(defn unix-timestamp->instant
  "Convert timestamp to Instant."
  [ts]
  (Instant/ofEpochSecond ts))

(defn instant->unix-timestamp
  "Convert timestamp to Instant."
  [instant]
  (-> instant .toEpochMilli (/ 1000) int))
;; => #'ieugen.nebula.time/instant->unix-timestamp


(defn now
  "Get the now as an ^Instant"
  []
  (Instant/now))

^:rct/test
(comment

  (str (unix-timestamp->instant 1712916991))
  ;; => "2024-04-12T10:16:31Z"

  (-> (unix-timestamp->instant 1712916991)
      instant->unix-timestamp)
  ;; => 1712916991
  )

(defn is-duration?
  "Return true if d is a ^Duration instance"
  [d]
  (instance? Duration d))

(defn pos-duration?
  "Return true if d is a ^Duration instance"
  [d]
  (when d
    (and (is-duration? d) 
         (not
          (or (.isZero d)
              (.isNegative d))))))

^:rct/test
(comment

  (pos-duration? Duration/ZERO)
  ;; => false

  (pos-duration? (Duration/parse "PT-1s"))
  ;; => false

  (pos-duration? (Duration/parse "PT1s"))
  ;; => true
  )


(defn expired?
  "Return true if given time is between not-before and not-after"
  [^Instant not-before ^Instant not-after ^Instant time]
  (let [in-interval (and
                     (.isBefore time not-after)
                     (.isAfter time not-before))]
    (not in-interval)))

^:rct/test
(comment

  (def base (Instant/now))
  (def before (.minusSeconds base 100))
  (def after (.plusSeconds base 100))

  (expired? before after base) ;; => false
  (expired? base before after) ;; => true
  (expired? after before base) ;; => true
  (expired? after base before) ;; => true
  )

(defn try-parse-duration
  "Try to parse a duration.
   Return duration on success.
   Return a Failure on exception."
  [duration]
  (f/try*
   (Duration/parse duration)))

(defn parse-duration
  "Parse a duration from string.
   Return a ^java.lang.Duration on success.
   Retun nil when string is blank or empty.
   Attempts to accept go time.Duration string format.

   Throw exception on parse failure."
  [duration-str]
  (let [duration-tries [duration-str
                        (str "PT" duration-str)
                        (str "P" duration-str)]
        duration (filter f/ok? (map try-parse-duration duration-tries))]
    (if (empty? duration)
      (f/fail "Failed to parse duration %s" duration-str)
      (first duration))))

^:rct/test
(comment

  (parse-duration nil)
  ;; => #failjure.core.Failure{:message "Failed to parse duration null"}

  (parse-duration "")
  ;; => #failjure.core.Failure{:message "Failed to parse duration "}

  (parse-duration "P")
  ;; => #failjure.core.Failure{:message "Failed to parse duration P"}

  (parse-duration "1")
  ;; => #failjure.core.Failure{:message "Failed to parse duration 1"}

  (str (parse-duration "-1s"))
  ;; => "PT-1S"

  (str (parse-duration "0s"))
  ;; => "PT0S"

  (str (parse-duration "1s"))
  ;; => "PT1S"

  (str (parse-duration "1d"))
  ;; => "PT24H"

  (str (parse-duration "5d"))
  ;; => "PT120H"

  (str (parse-duration "PT8760h0m0s"))
  ;; => "PT8760H"

  (str (parse-duration "8760h0m0s"))
  ;; => "PT8760H"
  
  )

(defn negative-or-zero-duration?
  "Return true is duration is positive or zero: <= 0"
  [^Duration d]
  (when d (or
           (.isZero d)
           (.isNegative d))))

(defn positive-duration?
  "Return true is duration is positive: > 0"
  [^Duration d]
  (when d
    (not (negative-or-zero-duration? d))))

^:rct/test
(comment

  (negative-or-zero-duration? (Duration/parse "PT-1s"))
  ;; => true

  (negative-or-zero-duration? Duration/ZERO)
  ;; => true

  (positive-duration? (Duration/parse "PT1s"))
  ;; => true

  (positive-duration? Duration/ZERO)
  ;; => false

  (positive-duration? (Duration/parse "PT-1s"))
  ;; => false
  )

(defn java-instant->iso-str
  "Format a java ^Instant to ISO DateTime"
  [^Instant instant]
  (let [d (OffsetDateTime/ofInstant instant (ZoneOffset/systemDefault))]
    (.format d DateTimeFormatter/ISO_OFFSET_DATE_TIME)))

(defn compute-cert-not-after
  "Cert NotAfter value is computed like:
   - now + duration - when now and a duration is specified
   - one second before given expiration of not-after, when not-after is specfidied
   - if now, not-after and duration are specified it will do one or the other
   based on whether duration is negative.

   Does not check if now + duration is past not-after."
  ([^Instant not-after]
   (.minusSeconds not-after 1))
  ([^Instant now ^Duration duration]
   (.plus now duration))
  ([^Instant now ^Instant not-after ^Duration duration]
   (if (negative-or-zero-duration? duration)
     (compute-cert-not-after not-after)
     (compute-cert-not-after now duration))))

^:rct/test
(comment

  (def my-now1 (Instant/parse "2024-04-10T09:00:00Z"))
  (def my-not-after1 (.plusSeconds my-now1 300))

  (str (compute-cert-not-after my-now1 my-not-after1 Duration/ZERO))
  ;; => "2024-04-10T09:04:59Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT-1s")))
  ;; => "2024-04-10T09:04:59Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT10s")))
  ;; => "2024-04-10T09:00:10Z"

  (str (compute-cert-not-after my-now1 my-not-after1 (Duration/parse "PT350s")))
  ;; => "2024-04-10T09:05:50Z"
  )