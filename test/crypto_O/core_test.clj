(ns crypto_O.core-test
  (:import [java.util Arrays])
  (:require [clojure.test :refer :all]
            [crypto_O.core :refer :all]))

(deftest test-rotate
  (testing "Rotating 4 bytes left"
    (let [input (int-array [1 2 3 4])
          output (rotate input)]
      (is (and (= (aget output 0) 2)
               (= (aget output 1) 3)
               (= (aget output 2) 4)
               (= (aget output 3) 1))))))

(deftest test-four-byte-xor
  (testing "smoketest xoring 4 bytes"
    (let [lhs (int-array [0xFF 0xFF 0xFF 0xFF])
          rhs (int-array [0xF0 0x0F 0x77 0x01])]
      (is (Arrays/equals (byte-xor lhs rhs)
                         (int-array  [0x0F 0xF0 0x88 0xFE]))))))

;;; yes this is cheesy... want minimal coverage outside the expected happy path before test.checking
(deftest test-one-byte-xor
  (testing "smoketest xoring 1 bytes"
    (let [lhs (int-array [0xFF])
          rhs (int-array [0xF0])]
      (is (Arrays/equals (byte-xor lhs rhs)
                         (int-array  [0x0F]))))))
