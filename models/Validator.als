module Validator
open DropboxAPI

// This module validates specific scenarios from the Dropbox API

// Scenario 1: User authentication and account information
pred userAccountScenario {
  // Create a test user
  some u: FullAccount | {
    u.email = "test@example.com"
    u.display_name = "Test User"
    u.account_type = Pro
    u.email_verified = True
    
    // Verify operations
    some op: GetCurrentAccountOperation | {
      op.performer = u
      op.result = u
    }
    
    some op: GetSpaceUsageOperation | {
      op.performer = u
      op.result_used > 0
      op.result_allocation > op.result_used
    }
  }
}

// Scenario 2: File operations
pred fileOperationsScenario {
  // Create users and files
  some u: User, f: File, fold: Folder | {
    u.email = "file_test@example.com"
    f.name = "test_file.txt"
    f.owner = u
    fold.name = "test_folder"
    fold.owner = u
    fold.contents = f
    
    // File operations
    some upload: UploadOperation | {
      upload.performer = u
      upload.target_path = "/test_folder/new_file.txt"
      upload.content = "Test content"
      upload.result_file.owner = u
      upload.result_file.path = "/test_folder/new_file.txt"
    }
    
    some list: ListFolderOperation | {
      list.performer = u
      list.path = "/test_folder"
      list.result = fold.contents
    }
    
    some download: DownloadOperation | {
      download.performer = u
      download.file = f
      download.success = True
    }
  }
}

// Scenario 3: Sharing
pred sharingScenario {
  // Create users and shared content
  some owner: User, viewer: User, f: File | {
    owner.email = "owner@example.com"
    viewer.email = "viewer@example.com"
    f.owner = owner
    f.name = "shared_doc.docx"
    
    // Share operation
    some share: ShareOperation | {
      share.performer = owner
      share.entry = f
      share.recipients = viewer
      share.access_level = Viewer
      
      // Check permissions created
      some p: Permission | {
        p in share.result_permissions
        p.user = viewer
        p.entry = f
        p.access_level = Viewer
      }
    }
    
    // Create shared link
    some link: CreateSharedLinkOperation | {
      link.performer = owner
      link.entry = f
      link.password = "secret"
      
      // Check link created
      link.result_link.target = f
      link.result_link.visibility = Password
    }
  }
}

// Scenario 4: Team operations
pred teamScenario {
  // Create team and members
  some t: Team, admin: User, member: User | {
    t.name = "Test Team"
    admin.email = "admin@company.com"
    admin.account_type = Business
    member.email = "member@company.com"
    member.account_type = Business
    
    // Team relationships
    t.members = admin + member
    admin.team = t
    member.team = t
    
    // Team folder
    some folder: Folder | {
      folder.name = "Team Folder"
      folder.owner = admin
      
      // Permissions
      some p1, p2: Permission | {
        p1.user = admin
        p1.entry = folder
        p1.access_level = Owner
        
        p2.user = member
        p2.entry = folder
        p2.access_level = Editor
      }
    }
  }
}

// Run all validation scenarios
run userAccountScenario for 5
run fileOperationsScenario for 5
run sharingScenario for 5
run teamScenario for 5

// Cross-validation to ensure no conflicts between scenarios
pred allScenariosValid {
  userAccountScenario
  fileOperationsScenario
  sharingScenario
  teamScenario
}

run allScenariosValid for 10
