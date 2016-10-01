;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; crypto_O Copyright (C) [2016] [Seth Schroeder]                                ;;
;;                                                                               ;;
;; http://www.samiam.org was the basis for much of this code. Problems are mine! ;;
;;                                                                               ;;
;; =====================> DO NOT USE THIS IN PRODUCTION!! <===================== ;;
;;                The correctness is iffy, and correct code can be insecure.     ;;
;;                Let's not even think about performance!                        ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ns crypto_O.core
  (:import [java.nio ByteBuffer]
           [java.nio.file Files FileSystem FileSystems]
           [java.security MessageDigest])
  (:require [clojure.math.numeric-tower :as math]) 
  (:refer-clojure))

(defn trace
  [msg thing]
  (println (apply str msg " " (map #(format "%02x" %) thing))))

(defn byte-shift-right [byte bits]
  (bit-and 0xff
           (int (/ byte
                   (math/expt 2 bits)))))

(defn byte-shift-left [byte bits]
  (int (bit-and 0xff
                (* (math/expt 2 bits) byte))))

(defn rotate [four-byte-array]
  (let [shunt (aget four-byte-array 0)]
    (doseq [index (range 1 4)
            :let [value (aget four-byte-array index)]]
      (aset-int four-byte-array (dec index) value))
    (aset-int four-byte-array 3 shunt)
    four-byte-array))
