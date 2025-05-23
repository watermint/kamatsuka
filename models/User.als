module User
open Util

// User representation in Dropbox API
sig User {
  id: one String,
  email: one String,
  display_name: one String,
  account_type: one AccountType
}

// Account types in Dropbox
enum AccountType {
  Basic,
  Pro,
  Business
}

// Full account information
sig FullAccount extends User {
  email_verified: one Bool,
  country: lone String,
  team: lone Team
}

// Basic account information (subset of full account)
sig BasicAccount extends User {
  // Basic account contains only essential user info
}

// Team representation
sig Team {
  id: one String,
  name: one String,
  members: set User
}

// Predicates and assertions for validation
pred validUser {
  all u: User | some u.id and some u.email
}

run validUser for 5
