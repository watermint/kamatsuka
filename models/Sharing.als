module Sharing
open User
open File
open Util

// Access levels in Dropbox
enum AccessLevel {
  Owner,
  Editor,
  Viewer,
  Commenter
}

// Permissions for shared content
sig Permission {
  user: one User,
  entry: one Entry,
  access_level: one AccessLevel
}

// Shared link
sig SharedLink {
  id: one String,
  url: one String,
  target: one Entry,
  expires: lone Int,  // Optional expiration timestamp
  password: lone String,  // Optional password protection
  visibility: one Visibility
}

// Visibility settings for sharing
enum Visibility {
  Public,
  TeamOnly,
  Password
}

// Team sharing settings
sig TeamSharingSettings {
  team: one User/Team,
  shared_folder_member_policy: one SharingPolicy,
  shared_folder_join_policy: one JoinPolicy,
  shared_link_create_policy: one CreatePolicy
}

// Sharing policies
enum SharingPolicy {
  Anyone,
  Team,
  TeamAndExternalUsers
}

enum JoinPolicy {
  FromAnyone,
  FromTeamOnly
}

enum CreatePolicy {
  DefaultPublic,
  DefaultTeamOnly,
  TeamOnlyPolicy
}

// Predicates and assertions
pred validSharing {
  // Every shared entry must have an owner
  all e: Entry | some p: Permission | p.entry = e and p.access_level = Owner
  
  // Owner must be unique per entry
  all e: Entry | one p: Permission | p.entry = e and p.access_level = Owner
  
  // No sharing conflicts - a user can't have multiple permissions for the same entry
  all u: User, e: Entry | lone p: Permission | p.user = u and p.entry = e
  
  // All shared links must point to a valid entry
  all l: SharedLink | one e: Entry | l.target = e
}

run validSharing for 5
