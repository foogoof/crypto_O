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
  (:import [java.util Arrays])
  (:require [crypto_O.core :as core]
            [crypto_O.galois-field :as galois])
  (:refer-clojure))

(declare expand-key expand-key-inner s-box)

(defn substitute-bytes [bytes]
  (reduce (fn [memo index]
            (aset-int memo index (s-box (aget memo index)))
            memo)
          (int-array (count bytes))
          (range (count bytes))))

(defn shift-rows [bytes]
  (let [row0 (int-array (Arrays/copyOfRange bytes 0 4))
        row1 (int-array (Arrays/copyOfRange bytes 4 8))
        row2 (int-array (Arrays/copyOfRange bytes 8 12))
        row3 (int-array (Arrays/copyOfRange bytes 12 16))]
    (doseq [row [row1 row2 row2 row3 row3 row3]]
      (core/rotate row))
    (int-array (concat row0 row1 row2 row3))))

(defn mix-columns [bytes]
  (let [columns (core/bytes-to-columns bytes)]
    (doseq [index (range 4)]
      (galois/mix-column (nth columns index)))
    (core/columns-to-bytes columns)))

(defn encrypt-first-rounds [bytes key]
  (-> bytes
      substitute-bytes
      shift-rows
      mix-columns
      (core/byte-xor key)))

(defn encrypt-last-round [bytes key]
  (-> bytes
      substitute-bytes
      shift-rows
      (core/byte-xor key)))

(defn decrypt-first-round [byte key])

(defn decrypt-last-rounds [byte key])

(defn get-key [bytes key-index]
  (let [starting-index (* 16 key-index)]
   (Arrays/copyOfRange bytes starting-index (+ 16 starting-index))))

(defn encrypt [key data]
  (let [raw-state (Arrays/copyOf data 16)
        keys  (expand-key key)
        initial-state (core/byte-xor raw-state (get-key keys 0))]
    (-> (reduce (fn [memo round-index]
                  (encrypt-first-rounds memo (get-key keys round-index)))
                initial-state
                (range 1 10))
        (encrypt-last-round (get-key keys 10)))))

(defn decrypt [key data]
  (let [raw-state (Arrays/copyOf data 16)
        keys (int-array (reverse (expand-key key))) ; FIXME: can't be good for perf
        initial-state (core/byte-xor raw-state (get-key keys 0))]
    (reduce (fn [prior-round current-round-index]
              (decrypt-last-rounds prior-round (get-key keys current-round-index)))
            (decrypt-first-round initial-state (get-key keys 1))
            (range 2 11))))

(defn expand-key [input]
  (let [output (int-array (* 11 16))]
    (doseq [index (range 16)
            :let [value (aget input index)]]
      (aset-int output index value))
    (expand-key-inner input output)))

(defn s-box-rotate [s_x _]
  (let [{:keys [s x]} s_x
        s-prime (bit-or (core/byte-shift-left s 1) (core/byte-shift-right s 7))]
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
