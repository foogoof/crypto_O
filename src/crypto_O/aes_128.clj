;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; crypto_O Copyright (C) [2016] [Seth Schroeder]                                ;;
;;                                                                               ;;
;; http://www.samiam.org was the basis for much of this code. Problems are mine! ;;
;;                                                                               ;;
;; =====================> DO NOT USE THIS IN PRODUCTION!! <===================== ;;
;;                The correctness is iffy, and correct code can be insecure.     ;;
;;                Let's not even think about performance!                        ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(ns crypto_O.aes-128
  (:require [crypto_O.core :as core]
            [crypto_O.galois-field :as galois])
  (:refer-clojure))

(declare expand-key-inner)

(defn expand-key [input]
  (let [output (int-array (* 11 16))]
    (doseq [index (range 16)
            :let [value (aget input index)]]
      (aset-int output index value))
    (expand-key-inner input output)))

(defn s-box-rotate [s_x _]
  (let [{:keys [s x]} s_x
        s-prime (bit-or (core/byte-shift-left s 1) (bit-shift-right s 7))]
    {:s s-prime
     :x (bit-xor x s-prime)}))

(defn s-box [input]
  (let [x (galois/multiply-inverse input)
        s x
        s-x-prime (reduce s-box-rotate {:s s :x x} (range 4))]
    (bit-xor 0x63 (:x s-x-prime))))

(defn schedule-core-loop [ioput]
  (doseq [index (range 4)
          :let [raw-value (aget ioput index)
                s-box-value (s-box raw-value)]]
    (aset-int ioput index s-box-value)))

(defn schedule-core [ioput index]
  (core/rotate ioput)
  (schedule-core-loop ioput)
  (aset-int ioput
            0
            (bit-xor (aget ioput 0)
                     (galois/rcon index))))

(defn write-key [output output-position state]
  (doseq [state-index (range 4)
          :let [state-val (aget state state-index)
                output-write-index (+ output-position state-index)
                output-read-index (- output-write-index 16)
                output-val (aget output output-read-index)]]
    (aset-int output
              output-write-index
              (bit-xor state-val output-val))))

(defn refresh-state [state input input-index]
  (doseq [state-index (range 4)
          :let [read-index (+ state-index input-index)]]
    (aset-int state
              state-index
              (aget input (- read-index 4)))))

(defn expand-key-inner [input output]
  (let [state (int-array 4)]
    (doseq [output-index (range 16 176 4)]
      (refresh-state state output output-index)
      (if (= 0 (mod output-index 16))
        (schedule-core state (/ output-index 16)))
      (write-key output output-index state))
    output))
