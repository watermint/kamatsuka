# Dropbox API Team Admin Mode Implementation Summary

## Overview

The Dropbox API Team specification has been updated to properly implement the difference between "admin-mode" authentication modes as specified in the official Dropbox documentation.

## Changes Made

### 1. File Organization
- Moved `dropbox-api-team.yaml` and `dropbox-api-individual.yaml` to the `openapi/` directory for better organization

### 2. Admin Mode Differentiation

The API now properly distinguishes between two admin authentication modes:

#### **Whole Team Mode** (`x-stone-select-admin-mode: whole_team`)
- **Headers Supported**: Both `Dropbox-API-Select-User` AND `Dropbox-API-Select-Admin`
- **Access Scope**: When using `Dropbox-API-Select-Admin`, admins can access:
  - Team folders
  - Team spaces  
  - Team members' home namespaces
- **Use Case**: Read-only endpoints that need comprehensive access to simplify referring to and traversing team-owned content

#### **Team Admin Mode** (`x-stone-select-admin-mode: team_admin`)
- **Headers Supported**: ONLY `Dropbox-API-Select-Admin` (removed `Dropbox-API-Select-User`)
- **Access Scope**: Admins can access:
  - Team folders
  - Team spaces
  - **NOT** team members' home namespaces
- **Use Case**: Mutable calls that perform actions requiring administrator privileges within team spaces

### 3. Specific Implementation Changes

#### For Team Admin Mode Endpoints:
- ✅ Removed `Dropbox-API-Select-User` header parameters (44 instances)
- ✅ Retained `Dropbox-API-Select-Admin` header parameters
- ✅ Updated descriptions to clarify: "This user endpoint can be called by team admins using the Dropbox-API-Select-Admin header. Team Admin mode: can access team folders and team spaces but not team members' home namespaces."

#### For Whole Team Mode Endpoints:
- ✅ Kept both `Dropbox-API-Select-User` and `Dropbox-API-Select-Admin` header parameters
- ✅ Updated descriptions to clarify: "This user endpoint can be called by team admins using Dropbox-API-Select-User or Dropbox-API-Select-Admin headers. Whole Team mode: when using Dropbox-API-Select-Admin, can access team folders, team spaces, and team members' home namespaces."

#### API Documentation:
- ✅ Updated main API description to explain both admin modes
- ✅ Added clear documentation about the differences between the two modes

### 4. Statistics

- **Total endpoints processed**: 47 endpoints
- **Team Admin mode endpoints**: 32 endpoints (44 method instances)
- **Whole Team mode endpoints**: 15 endpoints (16 method instances)
- **Header removals**: 44 `Dropbox-API-Select-User` headers removed from Team Admin mode endpoints
- **Description updates**: 60 endpoint descriptions updated

## Compliance with Official Documentation

This implementation now fully complies with the official Dropbox documentation requirements:

> "APIs with 'admin-mode' = 'team_admin' does not support Dropbox-API-Select-User."

> "Whole Team: The endpoint can access content of team folders and team spaces as well as the team members' home namespaces."

> "Team Admin: The endpoint can access content of team folders and team spaces but not the team members' home namespaces."

## Files Modified

- `openapi/dropbox-api-team.yaml` - Main implementation file with all admin mode changes
- API description updated to explain the two admin modes

## Verification

The implementation has been verified to ensure:
- Team Admin mode endpoints only have `Dropbox-API-Select-Admin` headers
- Whole Team mode endpoints have both headers
- All descriptions accurately reflect the capabilities and restrictions
- The `x-stone-select-admin-mode` extension values remain intact