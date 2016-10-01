;; (defprotocol Block
;;   (pretty [_])

;;   (int-val [_])
;;   (byte-val [_])

;;   (byte-count [_])
;;   (bit-count [_])

;;   (xor [_ block])
;;   (bit-xor [_ block]))

;; (declare make-128-bit-block)

;; (defrecord Block128bit
;;     [int bytes]

;;   Block
;;   (pretty [self] (format "%064x" (:int self)))
;;   (byte-count [_] 16)
;;   (bit-count [_] 128)
;;   (int-val [self] (:int self))
;;   (byte-val [self] (:byte self))
;;   (xor [self rhs]
;;     (make-128-bit-block (.xor (:int self) (:int rhs))))
;;   (bit-xor [self rhs]
;;     (xor self rhs))
;;   )

;; (defn make-128-bit-block [val]
;;   (if (= (class val) BigInteger)
;;     (map->Block128bit {:int val :bytes (.toByteArray val)})
;;     (map->Block128bit {:int (new BigInteger val) :bytes val})))

#_(defn encrypt-block [block key]
    (let [round-keys (expand-key key)
          leading-rounds (reduce (fn [state value] (encrypt-round state (round-keys value)))
                                 block
                                 (range 10))]
      (encrypt-final-round leading-rounds (round-keys 10))))

#_(defn encrypt-round [input round-key]
    (-> input
        (encrypt-final-round round-key)
        mix-column))

#_(defn encrypt-final-round [input round-key]
    (-> input
        (xor round-key)
        substitute-bytes
        shift-row))

;; (defn substitute-bytes [block])
;; (defn shift-row [block])
;; (defn mix-column [block])
;; (defn expand-key [key])

;; (format "%064x" (new java.math.BigInteger (hash-chain (reverse (split-file "path")))))
;; (def zeros (int-array 16))
;; (Arrays/fill zeros (int 0))
;; (def rando (int-array [0x69 0x20 0xe2 0x99 0xa5 0x20 0x2a 0x6d 0x65 0x6e 0x63 0x68 0x69 0x74 0x6f 0x2a]))
;; (def one-two (int-array [0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0a 0x0b 0x0c 0x0d 0x0e 0x0f]))
;; (def ones (int-array 16))
;; (Arrays/fill ones (int 0xFF))
