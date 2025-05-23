module Util

// Define our own boolean abstraction
abstract sig Bool {}
one sig True, False extends Bool {}

// Some common predicates
pred startsWith[s, p: String] {
  // This is a simplified representation since Alloy doesn't have built-in string operations
  // In real implementation, we would need a more detailed logic
}

// Bool operations
pred isTrue[b: Bool] {
  b = True
}

pred isFalse[b: Bool] {
  b = False
}
