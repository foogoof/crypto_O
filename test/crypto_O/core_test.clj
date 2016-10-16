(ns crypto_O.core-test
  (:import [java.util Arrays]
           [java.nio ShortBuffer])
  (:require [clojure.test :refer :all]
            [crypto_O.core :refer :all]))

(deftest test-rotate
  (testing "Rotating 4 bytes left"
    (let [input (ShortBuffer/wrap (short-array [1 2 3 4]))
          output (rotate input)]
      (is (and (= (.get output 0) 2)
               (= (.get output 1) 3)
               (= (.get output 2) 4)
               (= (.get output 3) 1))))))

(deftest test-four-byte-xor
  (testing "smoketest xoring 4 bytes"
    (let [lhs (fast-buffer-from [0xF0 0x0F 0x77 0x01])
          rhs (fast-buffer-from [0xFF 0xFF 0xFF 0xFF])]
      (is (.equals (byte-xor lhs rhs)
                   (fast-buffer-from [0x0F 0xF0 0x88 0xFE]))))))

;;; yes this is cheesy... want minimal coverage outside the expected happy path before test.checking
(deftest test-one-byte-xor
  (testing "smoketest xoring 1 bytes"
    (let [lhs (fast-buffer 1)
          rhs (fast-buffer 1)]
      (.put lhs (short 0xFF))
      (.put rhs (short 0xF0))
      (is (.equals (byte-xor lhs rhs)
                   (fast-buffer-from [0x0F]))))))
