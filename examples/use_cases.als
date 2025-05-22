/*
 * Use Cases for Dropbox API Analysis
 * 
 * This file contains specific scenarios to test against the Dropbox API model.
 */

open ../models/dropbox_api

// Use Case 1: Adding a user to a team folder
pred useCase1_AddUserToTeamFolder {
    some u: User, tf: TeamFolder {
        not (u in tf.team.members)
        canAddUserToTeamFolder[u, tf]
    }
}

// Use Case 2: External collaboration on team folder
pred useCase2_ExternalCollaboration {
    some eu: ExternalUser, tf: TeamFolder {
        eu -> Read in tf.permissions
    }
}

// Use Case 3: Nested team folder structure
pred useCase3_NestedFolders {
    some parent, child: TeamFolder {
        parent != child
        // Model parent-child relationship if needed
    }
}

// Use Case 4: Permission inheritance
pred useCase4_PermissionInheritance {
    some u: User, tf: TeamFolder {
        u -> Admin in tf.permissions
        u -> Write in tf.permissions
        u -> Read in tf.permissions
    }
}

// Run specific use cases
run useCase1_AddUserToTeamFolder for 5
run useCase2_ExternalCollaboration for 5
run useCase3_NestedFolders for 5
run useCase4_PermissionInheritance for 5