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
  (:import [java.nio ByteBuffer ShortBuffer]
           [java.util Arrays])
  (:require [clojure.math.numeric-tower :as math]) 
  (:refer-clojure))

(defn trace
  [msg thing]
  (println (apply str msg " " (map #(format "%02x" %) thing))))

(defn trace-buffer [msg buffer]
  (let [shunt (short-array (.limit buffer))
        clone (.duplicate buffer)]
    (.rewind clone)
    (.get clone shunt)
    (println (format "length: %d position: %d" (.limit buffer) (.position buffer)))
    (trace msg shunt)))

(defn byte-shift-right [byte bits]
  (bit-and 0xff
           (int (/ byte
                   (math/expt 2 bits)))))

(defn byte-shift-left [byte bits]
  (int (bit-and 0xff
                (* (math/expt 2 bits) byte))))

(defn byte-xor [ioput rhs]
  (doseq [index (range (.limit rhs))
          :let [left-val (.get ioput index)
                right-val (.get rhs index)]]
    (.put ioput index (short (bit-xor left-val right-val))))
  ioput)

(defn rotate [buffer]
  (let [shunt (.get buffer 0)]
    (.put buffer 0 (.get buffer 1))
    (.put buffer 1 (.get buffer 2))
    (.put buffer 2 (.get buffer 3))
    (.put buffer 3 shunt)))

(defn- extract-column [bytes row-index]
  (let [column (int-array 4)]
    (doseq [column-index (range 4)
            :let [scalar-index (+ row-index (* 4 column-index))]]
      (aset-int column
                column-index
                (aget bytes scalar-index)))
    column))

(defn bytes-to-columns [bytes]
  (map (fn [row-index]
         (extract-column bytes row-index))
       (range 4)))

(defn columns-to-bytes [columns]
  (let [bytes (int-array 16)]
    (doseq [column-index (range 4)
            row-index (range 4)
            :let [column (nth columns column-index)
                  scalar-index (+ row-index (* 4 column-index))
                  value (aget column row-index)]]
      (aset-int bytes scalar-index value))
    bytes))

(defn fast-buffer [byte-limit]
  (.asShortBuffer (ByteBuffer/allocateDirect (* 2 byte-limit))))

(defn fast-buffer-block []
  (fast-buffer (* 8 16)))

(defn fast-buffer-from [seq]
  (let [buffer (fast-buffer (count seq))]
    (doseq [index (range (count seq))]
      (.put buffer (short (nth seq index))))
    buffer))

(defn equal-buffers? [lhs rhs]
  (Arrays/equals (.array lhs) (.array rhs)))

(defn byte-indexes [column-index column-width]
  (map (fn [cell-index] (+ (* column-index column-width)
                           cell-index))
       (range column-width)))
