module DropboxAPI
open User
open File
open Sharing
open API

// Main state of the Dropbox system
one sig DropboxSystem {
  users: set User,
  teams: set User/Team,
  entries: set Entry,
  permissions: set Permission,
  shared_links: set SharedLink,
  operations: set Operation
}

// Global constraints
fact SystemConsistency {
  // All users referenced in permissions must exist in the system
  all p: Permission | p.user in DropboxSystem.users
  
  // All entries referenced in permissions must exist in the system
  all p: Permission | p.entry in DropboxSystem.entries
  
  // All shared links must reference an existing entry
  all l: SharedLink | l.target in DropboxSystem.entries
  
  // All operations must be performed by an existing user
  all op: Operation | op.performer in DropboxSystem.users
  
  // Team members must be valid users
  all t: User/Team | t.members in DropboxSystem.users
  
  // Entry owners must be valid users
  all e: Entry | e.owner in DropboxSystem.users
}

// Validate the entire model
pred validateDropboxAPI {
  validUser
  validFileSystem
  validSharing
  validOperations
  
  // Additional cross-model validation
  // Every file must have at least one permission (for the owner)
  all e: Entry | some p: Permission | p.entry = e and p.access_level = Owner
  
  // Team consistency
  all u: User | some u.team implies u in u.team.members
}

// Run validation
run validateDropboxAPI for 5 but exactly 1 DropboxSystem
