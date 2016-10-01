(ns crypto_O.core-test
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
