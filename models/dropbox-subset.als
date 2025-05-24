module dropbox_api

// Custom type definitions
abstract sig Bool {}
one sig True extends Bool {}
one sig False extends Bool {}

fact BooleanValues {
  // Ensure Bool is partitioned into True and False
  Bool = True + False
}

// Base signatures
abstract sig Operation {
  id: String,
  path: String,
  method: String,
  request: lone Request,
  responses: set Response
}

sig Request {
  content: univ
}

sig Response {
  status: Int,
  content: lone univ
}

// Core Dropbox entities
sig User {
  account_id: String,
  email: String,
  display_name: String,
  country: lone String,
  disabled: Bool
}

sig Path {
  value: String
}

sig File {
  path: Path,
  id: String,
  name: String,
  size: Int,
  last_modified: String,
  content_hash: String
}

sig Folder {
  path: Path,
  id: String,
  name: String
}

sig SharedFolder extends Folder {
  access_type: AccessType,
  shared_link_policy: SharedLinkPolicy,
  members: set Member
}

abstract sig AccessType {}
one sig Owner extends AccessType {}
one sig Editor extends AccessType {}
one sig Viewer extends AccessType {}

abstract sig SharedLinkPolicy {}
one sig Anyone extends SharedLinkPolicy {}
one sig TeamOnly extends SharedLinkPolicy {}
one sig NoOne extends SharedLinkPolicy {}

sig Member {
  user: User,
  access_type: AccessType
}

// Key API operations
one sig Operation_list_folder extends Operation {}

fact Operation_list_folder_FieldValues {
  Operation_list_folder.id = "list_folder"
  Operation_list_folder.path = "/files/list_folder"
  Operation_list_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder.responses
}

one sig Operation_get_metadata extends Operation {}

fact Operation_get_metadata_FieldValues {
  Operation_get_metadata.id = "get_metadata"
  Operation_get_metadata.path = "/files/get_metadata"
  Operation_get_metadata.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_metadata.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_metadata.responses
}

one sig Operation_upload extends Operation {}

fact Operation_upload_FieldValues {
  Operation_upload.id = "upload"
  Operation_upload.path = "/files/upload"
  Operation_upload.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload.responses
}

one sig Operation_share_folder extends Operation {}

fact Operation_share_folder_FieldValues {
  Operation_share_folder.id = "share_folder"
  Operation_share_folder.path = "/sharing/share_folder"
  Operation_share_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_share_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_share_folder.responses
}

// Global constraints
fact APIConstraints {
  // All operations must have unique IDs
  all disj op1, op2: Operation | op1.id != op2.id
  
  // Files and folders must have unique paths
  all disj f1, f2: File | f1.path != f2.path
  all disj f1, f2: Folder | f1.path != f2.path
  
  // A path cannot be both a file and a folder
  no f: File, d: Folder | f.path = d.path
  
  // All users must have unique account IDs
  all disj u1, u2: User | u1.account_id != u2.account_id
}

// Sample assertions for API verification
assert NoEmptyResponses {
  all op: Operation | some op.responses
}

assert SharedFoldersHaveMembers {
  all sf: SharedFolder | some sf.members
}

// Run commands for analysis
pred show {}
run show for 4 but 2 Operation, 3 User, 5 File, 3 Folder
check NoEmptyResponses for 4
check SharedFoldersHaveMembers for 4
