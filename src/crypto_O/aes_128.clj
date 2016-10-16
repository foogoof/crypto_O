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

(defn substitute-bytes [block]
  (doseq [index (range (.limit block))]
    (.put block index (s-box (.get block index))))
  block)

(defn extract-row [bytes row-index]
  (core/trace-buffer "er" bytes)
  (let [row (.limit (.slice bytes) 4)]
    (.position bytes (+ 4 (.position bytes)))
    row))

(defn shift-rows [bytes]
  (let [rows (map (fn [index] (extract-row bytes index)) (range 4))]
    (core/rotate (nth rows 1))
    (-> (core/rotate (nth rows 2))
        core/rotate)
    (-> (core/rotate (nth rows 3))
        core/rotate
        core/rotate))
  bytes)

(defn mix-columns [bytes]
  (doseq [index (range 4)]
    (galois/mix-column bytes index))
  bytes)

(defn encrypt-first-rounds [bytes key]
  (-> bytes
      substitute-bytes
      shift-rows
      mix-columns
      (core/byte-xor key)
      (.rewind)))

(defn encrypt-last-round [bytes key]
  (-> bytes
      substitute-bytes
      shift-rows
      (core/byte-xor key)
      (.rewind)))

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

(defn get-key [keys key-index]
  (.position keys (* key-index bytes-per-key))
  (.limit (.slice keys) bytes-per-key))

(defn encrypt-block [key block]
  (let [raw-state (core/fast-buffer-block)
        keys (expand-key key)
        state (core/byte-xor raw-state (get-key keys 0))]
    (doseq [round (range 1 10)
            :let [round-key (get-key keys round)]]
      (encrypt-first-rounds state key))
    (encrypt-last-round state (get-key keys 10))))

(defn decrypt-block [key block]
  (let [raw-state (Arrays/copyOf block 16)
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
  (dotimes [_ 4]
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
    (dotimes [_ (* 4 10)]
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
