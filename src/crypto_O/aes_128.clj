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
  (:import [java.util Arrays]
           [java.nio IntBuffer])
  (:require [crypto_O.core :as core]
            [crypto_O.galois-field :as galois])
  (:refer-clojure))

(def bytes-per-key (/ 128 8))

(declare expand-key expand-key-inner s-box flip-keys)

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

(defn decrypt-first-round [bytes key]
  (-> bytes
      shift-rows
      substitute-bytes
      (core/byte-xor key)))

(defn decrypt-last-rounds [bytes key]
  (-> bytes
      mix-columns
      shift-rows
      substitute-bytes
      (core/byte-xor key)))

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
        keys (flip-keys (expand-key key))
        initial-state (core/byte-xor raw-state (get-key keys 0))]
    (reduce (fn [prior-round current-round-index]
              (decrypt-last-rounds prior-round (get-key keys current-round-index)))
            (decrypt-first-round initial-state (get-key keys 1))
            (range 2 11))))

(defn make-key []
  (core/fast-buffer bytes-per-key))

(defn make-round-keys []
  (core/fast-buffer (* 11 bytes-per-key)))

(defn expand-key [key]
  (let [round-keys (make-round-keys)]
    (.put round-keys key)
    (expand-key-inner key round-keys)
    (.rewind key)
    (.rewind round-keys)))

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
          :let [raw-value (.get ioput index)
                s-box-value (s-box raw-value)]]
    (.put ioput index s-box-value)))

(defn schedule-core [state index]
  (core/rotate state)
  (schedule-core-loop state)
  (.put state
        0
        (bit-xor (.get state 0) (galois/rcon index)))
  (.rewind state))

(defn write-key [output output-position state]
  (doseq [state-index (range 4)
          :let [state-val (aget state state-index)
                output-write-index (+ output-position state-index)
                output-read-index (- output-write-index 16)
                output-val (aget output output-read-index)]]
    (aset-int output
              output-write-index
              (bit-xor state-val output-val))))

(defn refresh-state [state round-keys]
  (.rewind state)
  (.position round-keys (- (.position round-keys) 4))
  (doseq [_ (range 4)]
    (.put state (.get round-keys)))
  (.rewind state))

(defn write-partial-key [round-keys state]
  (let [write-index (.position round-keys)]
    (.rewind state)
    (doseq [index (range 4)
            :let [read-index (- (.position round-keys) 16)]]
      (.put round-keys
            (+ write-index index)
            (short (bit-xor (.get state index) (.get round-keys (+ index read-index))))))
    (.position round-keys (+ 4 (.position round-keys)))))


(defn expand-key-inner [key round-keys]
  (let [state (core/fast-buffer 4)]
    (doseq [_ (range 0 40)]
      (refresh-state state round-keys)
      (if (= 0 (mod (.position round-keys) 16))
        (schedule-core state (/ (.position round-keys) 16)))
      (write-partial-key round-keys state))))

(defn split-keys [keys]
  (map #(Arrays/copyOfRange keys (* 16 %) (+ 16 (* 16 %)))
       (range 11)))

(defn flip-keys [keys]
  #_(-> keys
        split-keys
        reverse
        concat
        int-array)
  []
  )
