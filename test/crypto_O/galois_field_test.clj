(ns crypto_O.galois-field-test
  (:require [clojure.test :refer :all]
            [crypto_O.galois-field :refer :all]))

(deftest test-multiply
  (testing "9 = 3 * 7"
    (is (= 9 (multiply 3 7)))))
