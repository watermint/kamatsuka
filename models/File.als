module File
open User
open Util

// File or folder in Dropbox
abstract sig Entry {
  id: one String,
  name: one String,
  path: one String,
  owner: one User
}

// File representation
sig File extends Entry {
  content: one String,
  size: one Int,
  modified: one Int,  // timestamp
  content_hash: one String
}

// Folder representation
sig Folder extends Entry {
  contents: set Entry
}

// File metadata
sig FileMetadata {
  file: one File,
  is_downloadable: one Bool,
  has_explicit_shared_members: one Bool
}

// Predicates and assertions
pred validFileSystem {
  // No entry can be its own parent (directly or indirectly)
  no f: Folder | f in f.^contents
  
  // Each entry except root has exactly one parent
  all e: Entry | lone f: Folder | e in f.contents
  
  // Path consistency
  all f: Folder, e: Entry | e in f.contents implies e.path.Util/startsWith[f.path]
}

run validFileSystem for 5
