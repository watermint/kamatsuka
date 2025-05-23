module API
open User
open File
open Sharing
open Util

// API operations that can be performed
abstract sig Operation {
  performer: one User,
  timestamp: one Int
}

// User operations
sig GetAccountOperation extends Operation {
  target_account_id: one String,
  result: lone User
}

sig GetCurrentAccountOperation extends Operation {
  result: lone FullAccount
}

sig GetSpaceUsageOperation extends Operation {
  result_used: one Int,
  result_allocation: one Int
}

// File operations
sig ListFolderOperation extends Operation {
  path: one String,
  recursive: one Bool,
  result: set Entry
}

sig DownloadOperation extends Operation {
  file: one File,
  success: one Bool
}

sig UploadOperation extends Operation {
  target_path: one String,
  content: one String,
  result_file: lone File
}

sig CreateFolderOperation extends Operation {
  path: one String,
  result_folder: lone Folder
}

sig DeleteOperation extends Operation {
  entry: one Entry,
  success: one Bool
}

// Sharing operations
sig ShareOperation extends Operation {
  entry: one Entry,
  recipients: set User,
  access_level: one AccessLevel,
  result_permissions: set Permission
}

sig CreateSharedLinkOperation extends Operation {
  entry: one Entry,
  password: lone String,
  expires: lone Int,
  result_link: lone SharedLink
}

// Operation constraints
pred validOperations {
  // User operations
  all op: GetAccountOperation | some u: User | u.id = op.target_account_id implies op.result = u
  
  // File operations
  all op: UploadOperation | (some f: File | f.path = op.target_path) implies op.success = True
  
  // Permission checks
  all op: ShareOperation | op.performer in (op.entry.owner) or 
    (some p: Permission | p.entry = op.entry and p.user = op.performer and p.access_level = Owner)
}

run validOperations for 5
