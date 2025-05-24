module api

// Generated from OpenAPI spec: Dropbox API
// Title: Dropbox API
// Version: 2.0

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

// Schema definitions
sig SharedFolderChangeLinkPolicyDetails {
  previous_value: lone SharedLinkPolicy,
  new_value: SharedLinkPolicy,
}


sig SharedFolderTransferOwnershipDetails {
  new_owner_email: EmailAddress,
  previous_owner_email: lone EmailAddress,
}


sig AlphaGetMetadataError {
  .tag: String,
}


sig TeamMergeFromDetails {
  team_name: String,
}


sig SearchV2Cursor {
  // Primitive type: string
  value: String
}


sig SharedContentRestoreInviteesDetails {
  shared_content_access_level: AccessLevel,
  invitees: set EmailAddress,
}


sig AccountCaptureChangeAvailabilityDetails {
  previous_value: lone AccountCaptureAvailability,
  new_value: AccountCaptureAvailability,
}


sig DeleteTeamInviteLinkDetails {
  link_url: String,
}


sig IntegrationDisconnectedDetails {
  integration_name: String,
}


sig DeviceSessionLogInfo {
  created: lone DropboxTimestamp,
  updated: lone DropboxTimestamp,
  ip_address: lone IpAddress,
}


sig MemberSpaceLimitsChangeStatusDetails {
  previous_value: SpaceLimitsStatus,
  new_value: SpaceLimitsStatus,
}


sig AddPropertiesError {
  .tag: String,
}


sig RansomwareRestoreProcessCompletedDetails {
  status: String,
  restored_files_count: Int,
  restored_files_failed_count: Int,
}


sig DomainVerificationAddDomainSuccessType {
  description: String,
}


sig FileTransfersTransferDeleteDetails {
  file_transfer_id: String,
}


sig MicrosoftOfficeAddinChangePolicyType {
  description: String,
}


sig MountFolderError {
  .tag: String,
}


sig FileCommentsChangePolicyDetails {
  new_value: FileCommentsPolicy,
  previous_value: lone FileCommentsPolicy,
}


sig UserFeatureValue {
  .tag: String,
}


sig FileTransfersFileAddDetails {
  file_transfer_id: String,
}


sig PaperDocUpdatePolicy {
  .tag: String,
}


sig MemberPermanentlyDeleteAccountContentsDetails {
}


sig RemoveTemplateArg {
  template_id: TemplateId,
}


sig MembersDeactivateBaseArg {
  user: UserSelectorArg,
}


sig FileEditCommentDetails {
  previous_comment_text: String,
  comment_text: lone String,
}


sig ShowcaseChangeExternalSharingPolicyDetails {
  previous_value: ShowcaseExternalSharingPolicy,
  new_value: ShowcaseExternalSharingPolicy,
}


sig PathToTags {
  path: Path,
  tags: set Tag,
}


sig TeamMergeRequestCanceledDetails {
  request_canceled_details: TeamMergeRequestCanceledExtraDetails,
}


sig ListFileMembersContinueError {
  .tag: String,
}


sig ReplayFileDeleteType {
  description: String,
}


sig PaperDocOwnershipChangedType {
  description: String,
}


sig SecondaryTeamRequestAcceptedDetails {
  primary_team: String,
  sent_by: String,
}


sig GroupCreateDetails {
  is_company_managed: lone Bool,
  join_policy: lone GroupJoinPolicy,
}


sig RansomwareAlertCreateReportDetails {
}


sig PaperAccessError {
  .tag: String,
}


sig FileSaveCopyReferenceDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig SharedFolderChangeMembersPolicyType {
  description: String,
}


sig TeamSelectiveSyncSettingsChangedType {
  description: String,
}


sig PaperDocChangeSharingPolicyDetails {
  event_uuid: String,
  team_sharing_policy: lone String,
  public_sharing_policy: lone String,
}


sig FileLockingPolicyChangedType {
  description: String,
}


sig RemoveCustomQuotaResult {
  .tag: String,
}


sig TeamSelectiveSyncSettingsChangedDetails {
  previous_value: SyncSetting,
  new_value: SyncSetting,
}


sig PaperEnabledUsersGroupAdditionDetails {
}


sig SfTeamUninviteType {
  description: String,
}


sig FilePermanentlyDeleteType {
  description: String,
}


sig OrganizeFolderWithTidyType {
  description: String,
}


sig TeamMergeToType {
  description: String,
}


sig TeamFolderIdArg {
  team_folder_id: SharedFolderId,
}


sig PaperDocExport {
  // Generic object with no specific type
}


sig DataResidencyMigrationRequestSuccessfulType {
  description: String,
}


sig IpAddress {
  // Primitive type: string
  value: String
}


sig UserFeature {
  .tag: String,
}


sig LegalHoldsListHeldRevisionsContinueArg {
  cursor: lone ListHeldRevisionCursor,
  id: LegalHoldId,
}


sig GroupCreation {
  .tag: String,
}


sig SharedFolderChangeMembersManagementPolicyDetails {
  new_value: AclUpdatePolicy,
  previous_value: lone AclUpdatePolicy,
}


sig MemberExternalId {
  // Primitive type: string
  value: String
}


sig PathOrLink {
  .tag: String,
}


sig SignInAsSessionEndDetails {
}


sig MemberSpaceLimitType {
  .tag: String,
}


sig TokenGetAuthenticatedAdminError {
  .tag: String,
}


sig TimeRange {
  end_time: lone DropboxTimestamp,
  start_time: lone DropboxTimestamp,
}


sig CreateFolderEntryResult {
  metadata: FolderMetadata,
}


sig FileLikeCommentType {
  description: String,
}


sig Feature {
  .tag: String,
}


sig TeamEncryptionKeyDeleteKeyType {
  description: String,
}


sig PollError {
  .tag: String,
}


sig FolderSubscriptionLevel {
  .tag: String,
}


sig UpdateTemplateResult {
  template_id: TemplateId,
}


sig LegalHoldsActivateAHoldDetails {
  name: String,
  legal_hold_id: String,
  end_date: lone DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig SharingPolicy {
  public_sharing_policy: lone SharingPublicPolicyType,
  team_sharing_policy: lone SharingTeamPolicyType,
}


sig StartedEnterpriseAdminSessionDetails {
  federation_extra_details: FedExtraDetails,
}


sig DomainInvitesEmailExistingUsersType {
  description: String,
}


sig EnterpriseSettingsLockingType {
  description: String,
}


sig ContextLogInfo {
  .tag: String,
}


sig TokenFromOAuth1Arg {
  oauth1_token: String,
  oauth1_token_secret: String,
}


sig Route {
  auth: String,
  scope: lone String,
  select_admin_mode: lone String,
  host: String,
  style: String,
  allow_app_folder_app: Bool,
  is_cloud_doc_auth: Bool,
  is_preview: Bool,
}


sig GroupMembersSetAccessTypeArg {
  // Generic object with no specific type
}


sig SearchOrderBy {
  .tag: String,
}


sig WebSessionsChangeActiveSessionLimitDetails {
  new_value: String,
  previous_value: String,
}


sig SmartSyncOptOutPolicy {
  .tag: String,
}


sig TeamGetInfoResult {
  num_provisioned_users: Int,
  name: String,
  team_id: String,
  num_used_licenses: Int,
  policies: TeamMemberPolicies,
  num_licensed_users: Int,
}


sig OutdatedLinkViewCreateReportType {
  description: String,
}


sig FileResolveCommentDetails {
  comment_text: lone String,
}


sig PaperCreateArg {
  import_format: ImportFormat,
  path: Path,
}


sig ListPaperDocsSortBy {
  .tag: String,
}


sig TeamMergeRequestAcceptedDetails {
  request_accepted_details: TeamMergeRequestAcceptedExtraDetails,
}


sig FileProviderMigrationPolicyState {
  .tag: String,
}


sig ExportInfo {
  export_as: lone String,
  export_options: lone set String,
}


sig TeamEncryptionKeyEnableKeyType {
  description: String,
}


sig PaperDocViewType {
  description: String,
}


sig DeviceChangeIpMobileDetails {
  device_session_info: lone DeviceSessionLogInfo,
}


sig GroupManagementType {
  .tag: String,
}


sig UnlockFileBatchArg {
  entries: set UnlockFileArg,
}


sig UserMembershipInfo {
  // Generic object with no specific type
}


sig ImportFormat {
  .tag: String,
}


sig PaperDocDeletedType {
  description: String,
}


sig ShowcaseViewType {
  description: String,
}


sig MobileDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig CountFileRequestsError {
  .tag: String,
}


sig FedHandshakeAction {
  .tag: String,
}


sig TeamFolderPermanentlyDeleteDetails {
}


sig UserOrTeamLinkedAppLogInfo {
  // Generic object with no specific type
}


sig ListTemplateResult {
  template_ids: set TemplateId,
}


sig GroupMemberSelectorError {
  .tag: String,
}


sig ListFolderGetLatestCursorResult {
  cursor: ListFolderCursor,
}


sig ListFolderCursor {
  // Primitive type: string
  value: String
}


sig SharedContentRemoveLinkExpiryDetails {
  previous_value: lone DropboxTimestamp,
}


sig ListFolderContinueArg {
  cursor: ListFolderCursor,
}


sig TfaRemoveBackupPhoneDetails {
}


sig DomainVerificationRemoveDomainType {
  description: String,
}


sig ShowcaseRestoredType {
  description: String,
}


sig GroupRemoveExternalIdDetails {
  previous_value: GroupExternalId,
}


sig ListFolderError {
  .tag: String,
}


sig AdminEmailRemindersChangedDetails {
  previous_value: AdminEmailRemindersPolicy,
  new_value: AdminEmailRemindersPolicy,
}


sig AddPaperDocUserMemberResult {
  result: AddPaperDocUserResult,
  member: MemberSelector,
}


sig SsoChangeCertType {
  description: String,
}


sig FileUnresolveCommentType {
  description: String,
}


sig AlertRecipientsSettingType {
  .tag: String,
}


sig SharingAllowlistRemoveArgs {
  domains: lone set String,
  emails: lone set String,
}


sig PaperFolderDeletedDetails {
  event_uuid: String,
}


sig PermanentDeleteChangePolicyType {
  description: String,
}


sig MemberChangeResellerRoleType {
  description: String,
}


sig TransferFolderArg {
  to_dropbox_id: DropboxId,
  shared_folder_id: SharedFolderId,
}


sig AdminAlertingAlertSensitivity {
  .tag: String,
}


sig SfExternalInviteWarnType {
  description: String,
}


sig ListRevisionsMode {
  .tag: String,
}


sig PaperDesktopPolicyChangedType {
  description: String,
}


sig AudienceRestrictingSharedFolder {
  name: String,
  audience: LinkAudience,
  shared_folder_id: SharedFolderId,
}


sig GeoLocationLogInfo {
  city: lone String,
  ip_address: IpAddress,
  region: lone String,
  country: lone String,
}


sig PaperDocResolveCommentType {
  description: String,
}


sig FileTransfersPolicyChangedType {
  description: String,
}


sig ContentAdministrationPolicyChangedDetails {
  new_value: String,
  previous_value: String,
}


sig DeleteAllClosedFileRequestsError {
  .tag: String,
}


sig LegalHoldsRemoveMembersDetails {
  legal_hold_id: String,
  name: String,
}


sig BinderRemovePageType {
  description: String,
}


sig ResellerSupportSessionEndDetails {
}


sig SharedContentAddMemberDetails {
  shared_content_access_level: AccessLevel,
}


sig BinderRenameSectionType {
  description: String,
}


sig SharingFileAccessError {
  .tag: String,
}


sig TeamMergeRequestAutoCanceledDetails {
  details: lone String,
}


sig MissingDetails {
  source_event_fields: lone String,
}


sig TeamId {
  // Primitive type: string
  value: String
}


sig FileLockMetadata {
  is_lockholder: lone Bool,
  created: lone DropboxTimestamp,
  lockholder_name: lone String,
  lockholder_account_id: lone AccountId,
}


sig NoteAclTeamLinkDetails {
}


sig EndedEnterpriseAdminSessionDetails {
}


sig SharedFolderDeclineInvitationType {
  description: String,
}


sig CreateSharedLinkError {
  .tag: String,
}


sig SearchMatch {
  metadata: Metadata,
  match_type: SearchMatchType,
}


sig GetActivityReport {
  // Generic object with no specific type
}


sig CreateFolderBatchResultEntry {
  .tag: String,
}


sig TeamProfileRemoveLogoType {
  description: String,
}


sig TimeUnit {
  .tag: String,
}


sig ShowcaseDownloadPolicy {
  .tag: String,
}


sig GuestAdminSignedInViaTrustedTeamsDetails {
  team_name: lone String,
  trusted_team_name: lone String,
}


sig FileRequestReceiveFileDetails {
  file_request_id: lone FileRequestId,
  submitter_email: lone EmailAddress,
  submitter_name: lone DisplayNameLegacy,
  file_request_details: lone FileRequestDetails,
  submitted_file_names: set String,
}


sig SharedLinkSettings {
  access: lone RequestedLinkAccessLevel,
  allow_download: lone Bool,
  expires: lone DropboxTimestamp,
  require_password: lone Bool,
  link_password: lone String,
  audience: lone LinkAudience,
  requested_visibility: lone RequestedVisibility,
}


sig TwoStepVerificationState {
  .tag: String,
}


sig SignInAsSessionStartType {
  description: String,
}


sig LegalHoldsChangeHoldNameDetails {
  previous_value: String,
  new_value: String,
  legal_hold_id: String,
}


sig FolderLinkMetadata {
  // Generic object with no specific type
}


sig ListUsersOnPaperDocResponse {
  doc_owner: UserInfo,
  has_more: Bool,
  cursor: Cursor,
  invitees: set InviteeInfoWithPermissionLevel,
  users: set UserInfoWithPermissionLevel,
}


sig SfAllowNonMembersToViewSharedLinksDetails {
  shared_folder_type: lone String,
  original_folder_name: String,
  target_asset_index: Int,
}


sig GetSharedLinkFileError {
  .tag: String,
}


sig AclUpdatePolicy {
  .tag: String,
}


sig PasswordStrengthRequirementsChangePolicyDetails {
  previous_value: PasswordStrengthPolicy,
  new_value: PasswordStrengthPolicy,
}


sig DeviceManagementEnabledType {
  description: String,
}


sig RevokeDesktopClientArg {
  // Generic object with no specific type
}


sig SfAddGroupType {
  description: String,
}


sig ShowcaseResolveCommentType {
  description: String,
}


sig ListFolderMembersArgs {
  // Generic object with no specific type
}


sig ShowcaseRemoveMemberDetails {
  event_uuid: String,
}


sig TeamProfileAddBackgroundDetails {
}


sig RevokeDeviceSessionArg {
  .tag: String,
}


sig GroupsSelector {
  .tag: String,
}


sig SharedNoteOpenedType {
  description: String,
}


sig SharingChangeLinkPolicyDetails {
  new_value: SharingLinkPolicy,
  previous_value: lone SharingLinkPolicy,
}


sig SfExternalInviteWarnDetails {
  new_sharing_permission: lone String,
  target_asset_index: Int,
  previous_sharing_permission: lone String,
  original_folder_name: String,
}


sig FileGetCopyReferenceType {
  description: String,
}


sig PaperDocDeleteCommentType {
  description: String,
}


sig DropboxTimestamp {
  // Primitive type: string
  value: String
}


sig PaperContentAddMemberDetails {
  event_uuid: String,
}


sig LinkedDeviceLogInfo {
  .tag: String,
}


sig TeamMemberId {
  // Primitive type: string
  value: String
}


sig FileRequestDeleteType {
  description: String,
}


sig LaunchResultBase {
  .tag: String,
}


sig AddSecondaryEmailResult {
  .tag: String,
}


sig RevokeDeviceSessionBatchArg {
  revoke_devices: set RevokeDeviceSessionArg,
}


sig TeamMergeRequestCanceledShownToSecondaryTeamDetails {
  sent_to: String,
  sent_by: String,
}


sig FailureDetailsLogInfo {
  user_friendly_message: lone String,
  technical_error_message: lone String,
}


sig UserTagsRemovedDetails {
  values: set String,
}


sig TeamEncryptionKeyCancelKeyDeletionType {
  description: String,
}


sig SsoRemoveLoginUrlDetails {
  previous_value: String,
}


sig TeamFolderChangeStatusType {
  description: String,
}


sig UserTagsRemovedType {
  description: String,
}


sig LinkPermissions {
  can_remove_password: lone Bool,
  can_remove_expiry: Bool,
  allow_download: Bool,
  can_allow_download: Bool,
  can_disallow_download: Bool,
  resolved_visibility: lone ResolvedVisibility,
  require_password: lone Bool,
  can_use_extended_sharing_controls: lone Bool,
  can_revoke: Bool,
  revoke_failure_reason: lone SharedLinkAccessFailureReason,
  allow_comments: Bool,
  can_set_password: lone Bool,
  can_set_expiry: Bool,
  effective_audience: lone LinkAudience,
  visibility_policies: set VisibilityPolicy,
  link_access_level: lone LinkAccessLevel,
  team_restricts_comments: Bool,
  audience_options: lone set LinkAudienceOption,
  requested_visibility: lone RequestedVisibility,
}


sig UserCustomQuotaArg {
  user: UserSelectorArg,
  quota_gb: UserQuota,
}


sig MemberSpaceLimitsChangeCustomQuotaDetails {
  new_value: Int,
  previous_value: Int,
}


sig SharingFolderJoinPolicy {
  .tag: String,
}


sig FileCopyType {
  description: String,
}


sig BinderReorderSectionDetails {
  binder_item_name: String,
  event_uuid: String,
  doc_title: String,
}


sig SharedContentChangeLinkPasswordType {
  description: String,
}


sig SyncSettingsError {
  .tag: String,
}


sig TeamMergeRequestExpiredShownToSecondaryTeamDetails {
  sent_to: String,
}


sig ContentSyncSettingArg {
  id: FileId,
  sync_setting: SyncSettingArg,
}


sig RateLimitError {
  reason: RateLimitReason,
  retry_after: Int,
}


sig GetThumbnailBatchResultEntry {
  .tag: String,
}


sig ListFolderLongpollError {
  .tag: String,
}


sig FileStatus {
  .tag: String,
}


sig TeamMergeRequestCanceledExtraDetails {
  .tag: String,
}


sig AddTagError {
  .tag: String,
}


sig SingleUserLock {
  created: DropboxTimestamp,
  lock_holder_account_id: AccountId,
  lock_holder_team_id: lone String,
}


sig UserInfo {
  same_team: Bool,
  display_name: String,
  team_member_id: lone String,
  account_id: AccountId,
  email: String,
}


sig TeamNamespacesListResult {
  namespaces: set NamespaceMetadata,
  cursor: String,
  has_more: Bool,
}


sig SharedContentClaimInvitationType {
  description: String,
}


sig LegalHoldId {
  // Primitive type: string
  value: String
}


sig SsoAddLoginUrlDetails {
  new_value: String,
}


sig TagText {
  // Primitive type: string
  value: String
}


sig FileTransfersFileAddType {
  description: String,
}


sig FileRequestsEmailsEnabledType {
  description: String,
}


sig JobStatus {
  .tag: String,
}


sig ExcludedUsersUpdateResult {
  status: ExcludedUsersUpdateStatus,
}


sig SharedFolderMemberPolicy {
  .tag: String,
}


sig AdminAlertGeneralStateEnum {
  .tag: String,
}


sig FileUnresolveCommentDetails {
  comment_text: lone String,
}


sig LegalHoldHeldRevisionMetadata {
  original_file_path: Path,
  author_email: EmailAddress,
  new_filename: String,
  author_member_status: TeamMemberStatus,
  original_revision_id: Rev,
  content_hash: Sha256HexHash,
  server_modified: DropboxTimestamp,
  author_member_id: TeamMemberId,
  file_type: String,
  size: Int,
}


sig NoteAclInviteOnlyDetails {
}


sig DeviceApprovalsChangeDesktopPolicyType {
  description: String,
}


sig FileDownloadDetails {
}


sig RewindPolicyChangedDetails {
  previous_value: RewindPolicy,
  new_value: RewindPolicy,
}


sig ListMemberAppsArg {
  team_member_id: String,
}


sig EmmChangePolicyDetails {
  new_value: EmmState,
  previous_value: lone EmmState,
}


sig TfaAddExceptionDetails {
}


sig DomainInvitesSetInviteNewUserPrefToNoType {
  description: String,
}


sig SfFbInviteType {
  description: String,
}


sig TeamSelectiveSyncPolicyChangedDetails {
  new_value: TeamSelectiveSyncPolicy,
  previous_value: TeamSelectiveSyncPolicy,
}


sig ListSharedLinksArg {
  path: lone ReadPath,
  direct_only: lone Bool,
  cursor: lone String,
}


sig LockFileBatchResult {
  // Generic object with no specific type
}


sig PasswordControlMode {
  .tag: String,
}


sig PathR {
  // Primitive type: string
  value: String
}


sig ShmodelEnableDownloadsType {
  description: String,
}


sig ListFolderMembersContinueError {
  .tag: String,
}


sig FileMemberRemoveActionResult {
  .tag: String,
}


sig FileUnlikeCommentDetails {
  comment_text: lone String,
}


sig MemberChangeMembershipTypeDetails {
  prev_value: TeamMembershipType,
  new_value: TeamMembershipType,
}


sig PaperCreateError {
  .tag: String,
}


sig EmmErrorDetails {
  error_details: FailureDetailsLogInfo,
}


sig SharingAllowlistAddArgs {
  domains: lone set String,
  emails: lone set String,
}


sig ExcludedUsersListError {
  .tag: String,
}


sig MountFolderArg {
  shared_folder_id: SharedFolderId,
}


sig AllowDownloadEnabledType {
  description: String,
}


sig ClassificationCreateReportDetails {
}


sig MembersSetProfilePhotoError {
  .tag: String,
}


sig ContentPermanentDeletePolicy {
  .tag: String,
}


sig MembersDataTransferArg {
  // Generic object with no specific type
}


sig ChangedEnterpriseConnectedTeamStatusType {
  description: String,
}


sig RemoveTagArg {
  tag_text: TagText,
  path: Path,
}


sig EventType {
  .tag: String,
}


sig RevokeLinkedApiAppArg {
  app_id: String,
  team_member_id: String,
  keep_app_folder: Bool,
}


sig SharingAllowlistListContinueError {
  .tag: String,
}


sig SharedLinkSettingsAllowDownloadEnabledDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
}


sig MetadataV2 {
  .tag: String,
}


sig DeviceApprovalsChangeMobilePolicyDetails {
  new_value: lone DeviceApprovalsPolicy,
  previous_value: lone DeviceApprovalsPolicy,
}


sig Name {
  abbreviated_name: String,
  given_name: String,
  surname: String,
  familiar_name: String,
  display_name: String,
}


sig AddFileMemberArgs {
  quiet: Bool,
  access_level: AccessLevel,
  file: PathOrId,
  add_message_as_comment: Bool,
  members: set MemberSelector,
  custom_message: lone String,
}


sig GetTemplateArg {
  template_id: TemplateId,
}


sig GpsCoordinates {
  longitude: Int,
  latitude: Int,
}


sig PropertiesError {
  .tag: String,
}


sig PaperDocumentLogInfo {
  doc_id: String,
  doc_title: String,
}


sig SharedFolderUnmountType {
  description: String,
}


sig UserSecondaryEmailsResult {
  user: UserSelectorArg,
  results: set AddSecondaryEmailResult,
}


sig RevokeDeviceSessionBatchResult {
  revoke_devices_status: set RevokeDeviceSessionStatus,
}


sig GetTagsResult {
  paths_to_tags: set PathToTags,
}


sig PaperDocAddCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig MembersTransferFormerMembersFilesError {
  .tag: String,
}


sig UpdateFolderMemberArg {
  access_level: AccessLevel,
  member: MemberSelector,
  shared_folder_id: SharedFolderId,
}


sig RevokeSharedLinkError {
  .tag: String,
}


sig GetSharedLinksResult {
  links: set LinkMetadata,
}


sig LegalHoldsChangeHoldDetailsType {
  description: String,
}


sig GroupsGetInfoItem {
  .tag: String,
}


sig SharingAllowlistListResponse {
  has_more: Bool,
  domains: set String,
  emails: set String,
  cursor: String,
}


sig FileRollbackChangesDetails {
}


sig ShowcasePermanentlyDeletedType {
  description: String,
}


sig LegalHoldsListHeldRevisionsContinueError {
  .tag: String,
}


sig SharedFolderMountType {
  description: String,
}


sig PrimaryTeamRequestAcceptedDetails {
  secondary_team: String,
  sent_by: String,
}


sig ShowcaseTrashedDeprecatedDetails {
  event_uuid: String,
}


sig PaperDocSharingPolicy {
  // Generic object with no specific type
}


sig GetMetadataArgs {
  shared_folder_id: SharedFolderId,
  actions: lone set FolderAction,
}


sig LinkAudienceOption {
  disallowed_reason: lone LinkAudienceDisallowedReason,
  audience: LinkAudience,
  allowed: Bool,
}


sig SmarterSmartSyncPolicyState {
  .tag: String,
}


sig ShmodelGroupShareDetails {
}


sig SfTeamJoinFromOobLinkDetails {
  sharing_permission: lone String,
  token_key: lone String,
  target_asset_index: Int,
  original_folder_name: String,
}


sig DropboxPasswordsPolicy {
  .tag: String,
}


sig MembersSetPermissions2Arg {
  user: UserSelectorArg,
  new_roles: lone set TeamMemberRoleId,
}


sig PasswordStrengthRequirementsChangePolicyType {
  description: String,
}


sig UploadSessionStartResult {
  session_id: String,
}


sig ResellerSupportSessionStartType {
  description: String,
}


sig UserSecondaryEmailsArg {
  secondary_emails: set EmailAddress,
  user: UserSelectorArg,
}


sig TeamMergeRequestAutoCanceledType {
  description: String,
}


sig FileRequestChangeDetails {
  previous_details: lone FileRequestDetails,
  new_details: FileRequestDetails,
  file_request_id: lone FileRequestId,
}


sig PaperContentPermanentlyDeleteDetails {
  event_uuid: String,
}


sig PaperDeploymentPolicy {
  .tag: String,
}


sig TeamFolderGetInfoItem {
  .tag: String,
}


sig LanguageCode {
  // Primitive type: string
  value: String
}


sig ShowcaseAddMemberType {
  description: String,
}


sig UpdateFolderMemberError {
  .tag: String,
}


sig SharePathError {
  .tag: String,
}


sig ResellerRole {
  .tag: String,
}


sig FeaturesGetValuesBatchError {
  .tag: String,
}


sig PaperExternalViewAllowDetails {
  event_uuid: String,
}


sig TeamActivityCreateReportFailType {
  description: String,
}


sig RelocationBatchError {
  .tag: String,
}


sig SsoChangeLogoutUrlType {
  description: String,
}


sig DeviceDeleteOnUnlinkSuccessType {
  description: String,
}


sig SecondaryTeamRequestReminderDetails {
  sent_to: String,
}


sig TfaRemoveExceptionDetails {
}


sig SearchV2Arg {
  include_highlights: lone Bool,
  match_field_options: lone SearchMatchFieldOptions,
  query: String,
  options: lone SearchOptions,
}


sig LegalHoldsReportAHoldType {
  description: String,
}


sig SharedLinkChangeVisibilityType {
  description: String,
}


sig SharedLinkDownloadType {
  description: String,
}


sig DeletedMetadata {
  // Generic object with no specific type
}


sig TeamFolderPermanentlyDeleteError {
  .tag: String,
}


sig DesktopClientSession {
  // Generic object with no specific type
}


sig ListTeamAppsError {
  .tag: String,
}


sig PaperUpdateArg {
  paper_revision: lone Int,
  path: WritePathOrId,
  import_format: ImportFormat,
  doc_update_policy: PaperDocUpdatePolicy,
}


sig MemberLinkedApps {
  linked_api_apps: set ApiApp,
  team_member_id: String,
}


sig IncludeMembersArg {
  return_members: Bool,
}


sig ExternalDriveBackupPolicyChangedDetails {
  new_value: ExternalDriveBackupPolicy,
  previous_value: ExternalDriveBackupPolicy,
}


sig SmartSyncOptOutType {
  description: String,
}


sig PaperContentPermanentlyDeleteType {
  description: String,
}


sig GovernancePolicyZipPartDownloadedType {
  description: String,
}


sig RateLimitReason {
  .tag: String,
}


sig PaperDocDownloadType {
  description: String,
}


sig TeamSelectiveSyncPolicyChangedType {
  description: String,
}


sig RelinquishFolderMembershipArg {
  shared_folder_id: SharedFolderId,
  leave_a_copy: Bool,
}


sig AuthError {
  .tag: String,
}


sig GroupsMembersListContinueArg {
  cursor: String,
}


sig ListUsersOnFolderResponse {
  users: set UserInfo,
  cursor: Cursor,
  has_more: Bool,
  invitees: set InviteeInfo,
}


sig ApiSessionLogInfo {
  request_id: RequestId,
}


sig CustomQuotaError {
  .tag: String,
}


sig RolloutMethod {
  .tag: String,
}


sig ExtendedVersionHistoryChangePolicyDetails {
  previous_value: lone ExtendedVersionHistoryPolicy,
  new_value: ExtendedVersionHistoryPolicy,
}


sig SharedLinkAddExpiryType {
  description: String,
}


sig DisplayNameLegacy {
  // Primitive type: string
  value: String
}


sig PaperChangeMemberPolicyDetails {
  previous_value: lone PaperMemberPolicy,
  new_value: PaperMemberPolicy,
}


sig NoteSharedDetails {
}


sig SsoAddLogoutUrlType {
  description: String,
}


sig LockFileError {
  .tag: String,
}


sig FolderOverviewDescriptionChangedType {
  description: String,
}


sig MemberSetProfilePhotoDetails {
}


sig UnshareFileArg {
  file: PathOrId,
}


sig SharedContentChangeDownloadsPolicyType {
  description: String,
}


sig SharingAllowlistListContinueArg {
  cursor: String,
}


sig WebSessionLogInfo {
  // Generic object with no specific type
}


sig ListMembersDevicesArg {
  include_desktop_clients: Bool,
  include_web_sessions: Bool,
  cursor: lone String,
  include_mobile_clients: Bool,
}


sig LegalHoldsReleaseAHoldType {
  description: String,
}


sig SharedContentRestoreMemberDetails {
  shared_content_access_level: AccessLevel,
}


sig LegalHoldPolicyName {
  // Primitive type: string
  value: String
}


sig TfaAddSecurityKeyDetails {
}


sig MemberRequestsChangePolicyDetails {
  new_value: MemberRequestsPolicy,
  previous_value: lone MemberRequestsPolicy,
}


sig TemplateFilterBase {
  .tag: String,
}


sig MemberSpaceLimitsChangeCustomQuotaType {
  description: String,
}


sig DeleteError {
  .tag: String,
}


sig CollectionShareType {
  description: String,
}


sig DeviceUnlinkDetails {
  display_name: lone String,
  delete_data: Bool,
  session_info: lone SessionLogInfo,
}


sig PaperFolderFollowedType {
  description: String,
}


sig PaperCreateResult {
  url: String,
  file_id: FileId,
  paper_revision: Int,
  result_path: String,
}


sig ListFolderMembersContinueArg {
  cursor: String,
}


sig FilePath {
  // Primitive type: string
  value: String
}


sig MemberAddV2Result {
  .tag: String,
}


sig TeamMergeRequestReminderType {
  description: String,
}


sig UnshareFolderError {
  .tag: String,
}


sig TwoStepVerificationPolicy {
  .tag: String,
}


sig DeviceApprovalsChangeUnlinkActionType {
  description: String,
}


sig NoteAclInviteOnlyType {
  description: String,
}


sig TeamSharingWhitelistSubjectsChangedType {
  description: String,
}


sig PreviewArg {
  path: ReadPath,
  rev: lone Rev,
}


sig SharedFolderMembersInheritancePolicy {
  .tag: String,
}


sig ExportMetadata {
  name: String,
  size: Int,
  paper_revision: lone Int,
  export_hash: lone Sha256HexHash,
}


sig UserRootInfo {
  // Generic object with no specific type
}


sig MemberSpaceLimitsChangeCapsTypePolicyDetails {
  previous_value: SpaceCapsType,
  new_value: SpaceCapsType,
}


sig PasswordChangeDetails {
}


sig MembersGetInfoV2Arg {
  members: set UserSelectorArg,
}


sig DeleteManualContactsArg {
  email_addresses: set EmailAddress,
}


sig DomainInvitesSetInviteNewUserPrefToYesType {
  description: String,
}


sig GroupMemberInfo {
  access_type: GroupAccessType,
  profile: MemberProfile,
}


sig LockFileResult {
  metadata: Metadata,
  lock: FileLock,
}


sig FileDeleteCommentDetails {
  comment_text: lone String,
}


sig PaperDocEditDetails {
  event_uuid: String,
}


sig OutdatedLinkViewCreateReportDetails {
  start_date: DropboxTimestamp,
  end_date: DropboxTimestamp,
}


sig SharedLinkDownloadDetails {
  shared_link_owner: lone UserLogInfo,
}


sig SharedContentRelinquishMembershipDetails {
}


sig PendingUploadMode {
  .tag: String,
}


sig FileLockingLockStatusChangedType {
  description: String,
}


sig PaperDocTrashedType {
  description: String,
}


sig AccountCaptureNotificationEmailsSentDetails {
  domain_name: String,
  notification_type: lone AccountCaptureNotificationType,
}


sig ListMemberDevicesError {
  .tag: String,
}


sig SharedContentAddInviteesType {
  description: String,
}


sig MemberSpaceLimitsAddCustomQuotaDetails {
  new_value: Int,
}


sig ClassificationChangePolicyType {
  description: String,
}


sig ExternalDriveBackupStatusChangedDetails {
  new_value: ExternalDriveBackupStatus,
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
  previous_value: ExternalDriveBackupStatus,
}


sig UploadSessionAppendError {
  .tag: String,
}


sig NoExpirationLinkGenReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig IntegrationDisconnectedType {
  description: String,
}


sig SharedFolderCreateType {
  description: String,
}


sig PropertiesSearchCursor {
  // Primitive type: string
  value: String
}


sig SfTeamInviteChangeRoleType {
  description: String,
}


sig UpdatePropertiesError {
  .tag: String,
}


sig SharedLinkCopyType {
  description: String,
}


sig UserFeaturesGetValuesBatchResult {
  values: set UserFeatureValue,
}


sig BaseDfbReport {
  start_date: String,
}


sig ListFolderLongpollResult {
  backoff: lone Int,
  changes: Bool,
}


sig SsoChangeCertDetails {
  new_certificate_details: Certificate,
  previous_certificate_details: lone Certificate,
}


sig MemberSpaceLimitsRemoveCustomQuotaType {
  description: String,
}


sig SharedContentRestoreMemberType {
  description: String,
}


sig TwoAccountChangePolicyDetails {
  new_value: TwoAccountPolicy,
  previous_value: lone TwoAccountPolicy,
}


sig ContentAdministrationPolicyChangedType {
  description: String,
}


sig TeamProfileChangeDefaultLanguageType {
  description: String,
}


sig TeamMergeRequestSentShownToPrimaryTeamType {
  description: String,
}


sig GroupInfo {
  // Generic object with no specific type
}


sig GetFileMetadataArg {
  file: PathOrId,
  actions: lone set FileAction,
}


sig ShowcaseResolveCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig DomainInvitesRequestToJoinTeamType {
  description: String,
}


sig SharedContentChangeLinkExpiryType {
  description: String,
}


sig TrustedTeamsRequestState {
  .tag: String,
}


sig FileRequestDeadline {
  allow_late_uploads: lone String,
  deadline: lone DropboxTimestamp,
}


sig TfaAddExceptionType {
  description: String,
}


sig SharedLinkSettingsAddPasswordDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig PaperContentRemoveFromFolderDetails {
  parent_asset_index: lone Int,
  event_uuid: String,
  target_asset_index: lone Int,
}


sig ResendSecondaryEmailResult {
  .tag: String,
}


sig DataPlacementRestrictionSatisfyPolicyType {
  description: String,
}


sig MemberSpaceLimitsChangeStatusType {
  description: String,
}


sig SharingInfo {
  read_only: Bool,
}


sig InvalidPropertyGroupError {
  .tag: String,
}


sig TeamMergeRequestRejectedShownToPrimaryTeamType {
  description: String,
}


sig EnforceLinkPasswordPolicy {
  .tag: String,
}


sig PropertiesSearchContinueArg {
  cursor: PropertiesSearchCursor,
}


sig ShowcaseChangeDownloadPolicyDetails {
  previous_value: ShowcaseDownloadPolicy,
  new_value: ShowcaseDownloadPolicy,
}


sig ListFileRequestsArg {
  limit: Int,
}


sig LegalHoldsExportCancelledDetails {
  legal_hold_id: String,
  export_name: String,
  name: String,
}


sig SharedLinkMetadata {
  link_permissions: LinkPermissions,
  id: lone Id,
  name: String,
  expires: lone DropboxTimestamp,
  path_lower: lone String,
  url: String,
  team_member_info: lone TeamMemberInfo,
  content_owner_team_info: lone TeamInfo,
}


sig LegalHoldPolicy {
  name: LegalHoldPolicyName,
  end_date: lone DropboxTimestamp,
  members: MembersInfo,
  activation_time: lone DropboxTimestamp,
  status: LegalHoldStatus,
  start_date: DropboxTimestamp,
  id: LegalHoldId,
  description: lone LegalHoldPolicyDescription,
}


sig EchoResult {
  result: String,
}


sig RansomwareAlertCreateReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig SyncSettingArg {
  .tag: String,
}


sig ListFileRequestsError {
  .tag: String,
}


sig TeamEncryptionKeyCancelKeyDeletionDetails {
}


sig MemberChangeExternalIdDetails {
  previous_value: MemberExternalId,
  new_value: MemberExternalId,
}


sig PaperDocRequestAccessDetails {
  event_uuid: String,
}


sig TeamProfileChangeBackgroundDetails {
}


sig DeleteArg {
  path: WritePathOrId,
  parent_rev: lone Rev,
}


sig TeamMergeRequestCanceledType {
  description: String,
}


sig GetTeamEventsArg {
  limit: Int,
  account_id: lone AccountId,
  time: lone TimeRange,
  category: lone EventCategory,
  event_type: lone EventTypeArg,
}


sig UserLinkedAppLogInfo {
  // Generic object with no specific type
}


sig EmailIngestReceiveFileDetails {
  from_email: lone EmailAddress,
  attachment_names: set String,
  from_name: lone DisplayNameLegacy,
  inbox_name: String,
  subject: lone String,
}


sig PermissionDeniedReason {
  .tag: String,
}


sig ReplayProjectTeamDeleteDetails {
}


sig DropboxPasswordsExportedType {
  description: String,
}


sig ExcludedUsersUpdateArg {
  users: lone set UserSelectorArg,
}


sig ShowcaseCreatedDetails {
  event_uuid: String,
}


sig SharedContentRestoreInviteesType {
  description: String,
}


sig NoteAclLinkDetails {
}


sig AdminAlertingChangedAlertConfigDetails {
  alert_name: String,
  previous_alert_config: AdminAlertingAlertConfiguration,
  new_alert_config: AdminAlertingAlertConfiguration,
}


sig TeamMergeRequestExpiredExtraDetails {
  .tag: String,
}


sig GroupMovedDetails {
}


sig DeleteTeamInviteLinkType {
  description: String,
}


sig FileTransfersTransferSendType {
  description: String,
}


sig ExternalDriveBackupPolicy {
  .tag: String,
}


sig GovernancePolicyCreateDetails {
  folders: lone set String,
  governance_policy_id: String,
  name: String,
  policy_type: lone PolicyType,
  duration: DurationLogInfo,
}


sig ApplyNamingConventionType {
  description: String,
}


sig PaperContentRemoveFromFolderType {
  description: String,
}


sig ListMemberAppsError {
  .tag: String,
}


sig AppLogInfo {
  display_name: lone String,
  app_id: lone AppId,
}


sig GovernancePolicyExportRemovedDetails {
  policy_type: lone PolicyType,
  export_name: String,
  name: String,
  governance_policy_id: String,
}


sig PaperDocUnresolveCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig ListFileMembersBatchArg {
  limit: Int,
  files: set PathOrId,
}


sig SmartSyncChangePolicyType {
  description: String,
}


sig CreateSharedLinkWithSettingsArg {
  path: ReadPath,
  settings: lone SharedLinkSettings,
}


sig RelocationPath {
  to_path: WritePathOrId,
  from_path: WritePathOrId,
}


sig PaperDocMentionDetails {
  event_uuid: String,
}


sig SharedNoteOpenedDetails {
}


sig SecondaryEmailVerifiedType {
  description: String,
}


sig PathLinkMetadata {
  // Generic object with no specific type
}


sig ModifySharedLinkSettingsError {
  .tag: String,
}


sig SecondaryMailsPolicyChangedType {
  description: String,
}


sig FileRequestsChangePolicyType {
  description: String,
}


sig ListFileRequestsResult {
  file_requests: set FileRequest,
}


sig GetSharedLinksError {
  .tag: String,
}


sig TeamBrandingPolicyChangedType {
  description: String,
}


sig MembersRemoveArg {
  // Generic object with no specific type
}


sig DeleteBatchResult {
  // Generic object with no specific type
}


sig ShowcaseFileDownloadDetails {
  download_type: String,
  event_uuid: String,
}


sig PaperDocUntrashedType {
  description: String,
}


sig SaveCopyReferenceError {
  .tag: String,
}


sig Id {
  // Generic object with no specific type
}


sig SfTeamInviteType {
  description: String,
}


sig DeleteBatchJobStatus {
  .tag: String,
}


sig RansomwareRestoreProcessCompletedType {
  description: String,
}


sig PaperDocDeleteCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig SharedFolderChangeLinkPolicyType {
  description: String,
}


sig DesktopSessionLogInfo {
  // Generic object with no specific type
}


sig DomainVerificationRemoveDomainDetails {
  domain_names: set String,
}


sig PaperDocTeamInviteDetails {
  event_uuid: String,
}


sig RelocationArg {
  // Generic object with no specific type
}


sig AppUnlinkTeamType {
  description: String,
}


sig TeamMergeRequestExpiredType {
  description: String,
}


sig SharedLinkSettingsRemoveExpirationDetails {
  shared_content_link: lone String,
  previous_value: lone DropboxTimestamp,
  shared_content_access_level: AccessLevel,
}


sig DataPlacementRestrictionChangePolicyType {
  description: String,
}


sig SharingAllowlistListError {
}


sig UploadError {
  .tag: String,
}


sig ListFileRequestsV2Result {
  cursor: String,
  file_requests: set FileRequest,
  has_more: Bool,
}


sig TeamNamespacesListContinueArg {
  cursor: String,
}


sig TeamMemberRoleId {
  // Primitive type: string
  value: String
}


sig RelocationBatchResult {
  // Generic object with no specific type
}


sig PolicyType {
  .tag: String,
}


sig LegalHoldsListPoliciesResult {
  policies: set LegalHoldPolicy,
}


sig AdminAlertSeverityEnum {
  .tag: String,
}


sig MembersListError {
  .tag: String,
}


sig PaperDesktopPolicy {
  .tag: String,
}


sig MemberSendInvitePolicy {
  .tag: String,
}


sig ObjectLabelRemovedType {
  description: String,
}


sig FederationStatusChangeAdditionalInfo {
  .tag: String,
}


sig RelocationBatchArg {
  // Generic object with no specific type
}


sig FileMemberActionResult {
  invitation_signature: lone set String,
  sckey_sha1: lone String,
  result: FileMemberActionIndividualResult,
  member: MemberSelector,
}


sig TeamMergeRequestAcceptedShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_by: String,
}


sig SharingAllowlistListArg {
  limit: Int,
}


sig SmartSyncNotOptOutType {
  description: String,
}


sig AccountCaptureMigrateAccountDetails {
  domain_name: String,
}


sig GroupChangeManagementTypeType {
  description: String,
}


sig MicrosoftOfficeAddinPolicy {
  .tag: String,
}


sig FileRevertDetails {
}


sig TeamMergeFromType {
  description: String,
}


sig NamespaceRelativePathLogInfo {
  relative_path: lone FilePath,
  is_shared_namespace: lone Bool,
  ns_id: lone NamespaceId,
}


sig MembersGetInfoArgs {
  members: set UserSelectorArg,
}


sig GroupChangeExternalIdDetails {
  previous_value: GroupExternalId,
  new_value: GroupExternalId,
}


sig UserGeneratedTag {
  tag_text: TagText,
}


sig DeleteAllClosedFileRequestsResult {
  file_requests: set FileRequest,
}


sig PasswordResetDetails {
}


sig BinderRenamePageType {
  description: String,
}


sig GroupId {
  // Primitive type: string
  value: String
}


sig ViewerInfoPolicy {
  .tag: String,
}


sig LegalHoldsExportAHoldType {
  description: String,
}


sig PaperApiBaseError {
  .tag: String,
}


sig AddPropertiesArg {
  property_groups: set PropertyGroup,
  path: PathOrId,
}


sig SharingChangeLinkEnforcePasswordPolicyDetails {
  new_value: ChangeLinkExpirationPolicy,
  previous_value: lone ChangeLinkExpirationPolicy,
}


sig ListMembersAppsArg {
  cursor: lone String,
}


sig RemovePropertiesError {
  .tag: String,
}


sig UploadSessionFinishBatchLaunch {
  .tag: String,
}


sig GovernancePolicyAddFolderFailedDetails {
  name: String,
  governance_policy_id: String,
  policy_type: lone PolicyType,
  folder: String,
  reason: lone String,
}


sig ShowcaseTrashedType {
  description: String,
}


sig LegalHoldsAddMembersType {
  description: String,
}


sig InsufficientPlan {
  upsell_url: lone String,
  message: String,
}


sig MemberSpaceLimitsChangeCapsTypePolicyType {
  description: String,
}


sig TeamFolderInvalidStatusError {
  .tag: String,
}


sig FileDeleteDetails {
}


sig SharedContentRelinquishMembershipType {
  description: String,
}


sig ShowcaseRequestAccessType {
  description: String,
}


sig LoginMethod {
  .tag: String,
}


sig DocLookupError {
  .tag: String,
}


sig TeamEncryptionKeyRotateKeyType {
  description: String,
}


sig TeamEncryptionKeyEnableKeyDetails {
}


sig AccountType {
  .tag: String,
}


sig OutdatedLinkViewReportFailedType {
  description: String,
}


sig ComputerBackupPolicyChangedDetails {
  new_value: ComputerBackupPolicy,
  previous_value: ComputerBackupPolicy,
}


sig SsoAddCertDetails {
  certificate_details: Certificate,
}


sig DomainInvitesSetInviteNewUserPrefToYesDetails {
}


sig RevokeDeviceSessionBatchError {
  .tag: String,
}


sig WebSessionsChangeFixedLengthPolicyDetails {
  previous_value: lone WebSessionsFixedLengthPolicy,
  new_value: lone WebSessionsFixedLengthPolicy,
}


sig SharedContentCopyType {
  description: String,
}


sig SharedContentClaimInvitationDetails {
  shared_content_link: lone String,
}


sig SsoChangeLoginUrlDetails {
  new_value: String,
  previous_value: String,
}


sig ListFilesContinueArg {
  cursor: String,
}


sig LoginFailType {
  description: String,
}


sig MemberSendInvitePolicyChangedType {
  description: String,
}


sig EventTypeArg {
  .tag: String,
}


sig GetSharedLinksArg {
  path: lone String,
}


sig GovernancePolicyContentDisposedType {
  description: String,
}


sig FileLinkMetadata {
  // Generic object with no specific type
}


sig SfInviteGroupType {
  description: String,
}


sig ListMembersAppsError {
  .tag: String,
}


sig PaperFolderTeamInviteDetails {
  event_uuid: String,
}


sig SharedLinkSettingsChangeAudienceType {
  description: String,
}


sig AccountCaptureMigrateAccountType {
  description: String,
}


sig Cursor {
  value: String,
  expiration: lone DropboxTimestamp,
}


sig ShowcaseUntrashedDeprecatedType {
  description: String,
}


sig PrimaryTeamRequestExpiredDetails {
  secondary_team: String,
  sent_by: String,
}


sig AddFolderMemberArg {
  custom_message: lone String,
  members: set AddMember,
  quiet: Bool,
  shared_folder_id: SharedFolderId,
}


sig PaperFolderFollowedDetails {
  event_uuid: String,
}


sig PhotoMetadata {
  // Generic object with no specific type
}


sig Sha256HexHash {
  // Primitive type: string
  value: String
}


sig SignInAsSessionEndType {
  description: String,
}


sig SsoAddLoginUrlType {
  description: String,
}


sig SharedFolderNestType {
  description: String,
}


sig FileDownloadType {
  description: String,
}


sig ExportMembersReportDetails {
}


sig PaperDocEditCommentType {
  description: String,
}


sig DropboxId {
  // Primitive type: string
  value: String
}


sig AccountCaptureRelinquishAccountType {
  description: String,
}


sig DataResidencyMigrationRequestUnsuccessfulType {
  description: String,
}


sig GroupType {
  .tag: String,
}


sig ShowcaseEditCommentType {
  description: String,
}


sig GetAccountBatchError {
  .tag: String,
}


sig EventDetails {
  .tag: String,
}


sig DevicesActive {
  linux: NumberPerDay,
  ios: NumberPerDay,
  windows: NumberPerDay,
  total: NumberPerDay,
  macos: NumberPerDay,
  android: NumberPerDay,
  other: NumberPerDay,
}


sig SharedContentRequestAccessDetails {
  shared_content_link: lone String,
}


sig GroupUserManagementChangePolicyDetails {
  new_value: GroupCreation,
  previous_value: lone GroupCreation,
}


sig DeleteBatchArg {
  entries: set DeleteArg,
}


sig GetTeamEventsError {
  .tag: String,
}


sig ShmodelDisableDownloadsDetails {
  shared_link_owner: lone UserLogInfo,
}


sig DataResidencyMigrationRequestSuccessfulDetails {
}


sig FolderLinkRestrictionPolicyChangedType {
  description: String,
}


sig TeamMemberInfoV2 {
  roles: lone set TeamMemberRole,
  profile: TeamMemberProfile,
}


sig SharingChangeLinkAllowChangeExpirationPolicyType {
  description: String,
}


sig RemoveMemberJobStatus {
  .tag: String,
}


sig SearchResult {
  more: Bool,
  matches: set SearchMatch,
  start: Int,
}


sig ShowcaseFileAddedDetails {
  event_uuid: String,
}


sig GovernancePolicyEditDetailsDetails {
  governance_policy_id: String,
  attribute: String,
  previous_value: String,
  new_value: String,
  name: String,
  policy_type: lone PolicyType,
}


sig TeamFolderArchiveJobStatus {
  .tag: String,
}


sig GetTemporaryLinkError {
  .tag: String,
}


sig CreateTeamInviteLinkDetails {
  link_url: String,
  expiry_date: String,
}


sig AccountCaptureChangeAvailabilityType {
  description: String,
}


sig GovernancePolicyExportRemovedType {
  description: String,
}


sig MinimalFileLinkMetadata {
  url: String,
  id: lone Id,
  path: lone String,
  rev: Rev,
}


sig UsersSelectorArg {
  .tag: String,
}


sig MemberSuggestDetails {
  suggested_members: set EmailAddress,
}


sig GroupSelectorError {
  .tag: String,
}


sig SharedLinkSettingsError {
  .tag: String,
}


sig SharedContentAddLinkPasswordDetails {
}


sig RelocationResult {
  // Generic object with no specific type
}


sig SmartSyncNotOptOutDetails {
  previous_value: SmartSyncOptOutPolicy,
  new_value: SmartSyncOptOutPolicy,
}


sig AppLinkTeamType {
  description: String,
}


sig AccountCaptureNotificationEmailsSentType {
  description: String,
}


sig PaperContentAddMemberType {
  description: String,
}


sig ThumbnailMode {
  .tag: String,
}


sig SharedLinkRemoveExpiryDetails {
  previous_value: lone DropboxTimestamp,
}


sig EmmChangePolicyType {
  description: String,
}


sig ShowcaseRenamedDetails {
  event_uuid: String,
}


sig PaperFolderTeamInviteType {
  description: String,
}


sig GetCopyReferenceError {
  .tag: String,
}


sig SearchMatchType {
  .tag: String,
}


sig AppBlockedByPermissionsDetails {
  app_info: AppLogInfo,
}


sig ShowcaseUntrashedDeprecatedDetails {
  event_uuid: String,
}


sig FileRequestsEmailsRestrictedToTeamOnlyDetails {
}


sig SsoChangeLoginUrlType {
  description: String,
}


sig GroupMembersChangeResult {
  group_info: GroupFullInfo,
  async_job_id: AsyncJobId,
}


sig MemberAddV2Arg {
  // Generic object with no specific type
}


sig MemberSpaceLimitsRemoveCustomQuotaDetails {
}


sig FileRequestDetails {
  asset_index: Int,
  deadline: lone FileRequestDeadline,
}


sig SharedLinkSettingsAddExpirationDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
  new_value: lone DropboxTimestamp,
}


sig MicrosoftOfficeAddinChangePolicyDetails {
  new_value: MicrosoftOfficeAddinPolicy,
  previous_value: lone MicrosoftOfficeAddinPolicy,
}


sig ThumbnailSize {
  .tag: String,
}


sig BinderAddSectionDetails {
  doc_title: String,
  event_uuid: String,
  binder_item_name: String,
}


sig ShowcaseFileRemovedType {
  description: String,
}


sig DirectoryRestrictionsRemoveMembersDetails {
}


sig MemberAddExternalIdDetails {
  new_value: MemberExternalId,
}


sig PaperExternalViewAllowType {
  description: String,
}


sig GroupsPollError {
  .tag: String,
}


sig UploadSessionStartBatchArg {
  num_sessions: Int,
  session_type: lone UploadSessionType,
}


sig DownloadPolicyType {
  .tag: String,
}


sig Team {
  id: String,
  name: String,
}


sig DeleteFileRequestArgs {
  ids: set FileRequestId,
}


sig PaperContentArchiveType {
  description: String,
}


sig ShowcaseDocumentLogInfo {
  showcase_id: String,
  showcase_title: String,
}


sig SharingTeamPolicyType {
  .tag: String,
}


sig FolderOverviewItemUnpinnedType {
  description: String,
}


sig GroupChangeExternalIdType {
  description: String,
}


sig ReplayFileSharedLinkModifiedType {
  description: String,
}


sig MembersAddArgBase {
  force_async: Bool,
}


sig LabelType {
  .tag: String,
}


sig DeleteManualContactsError {
  .tag: String,
}


sig UploadSessionFinishBatchResultEntry {
  .tag: String,
}


sig SharedContentUnshareDetails {
}


sig SharedLinkViewType {
  description: String,
}


sig TeamMergeRequestAcceptedShownToSecondaryTeamType {
  description: String,
}


sig OrganizationName {
  organization: String,
}


sig PaperChangeMemberPolicyType {
  description: String,
}


sig AdminAlertingTriggeredAlertDetails {
  alert_instance_id: String,
  alert_name: String,
  alert_severity: AdminAlertSeverityEnum,
  alert_category: AdminAlertCategoryEnum,
}


sig PendingSecondaryEmailAddedDetails {
  secondary_email: EmailAddress,
}


sig ShareFolderLaunch {
  .tag: String,
}


sig EmailIngestPolicyChangedDetails {
  new_value: EmailIngestPolicy,
  previous_value: EmailIngestPolicy,
}


sig WebSessionsChangeActiveSessionLimitType {
  description: String,
}


sig MembersListArg {
  include_removed: Bool,
  limit: Int,
}


sig UploadSessionLookupError {
  .tag: String,
}


sig TeamExtensionsPolicyChangedDetails {
  previous_value: TeamExtensionsPolicy,
  new_value: TeamExtensionsPolicy,
}


sig MembersSetProfileError {
  .tag: String,
}


sig PaperEnabledUsersGroupRemovalType {
  description: String,
}


sig SendForSignaturePolicyChangedDetails {
  previous_value: SendForSignaturePolicy,
  new_value: SendForSignaturePolicy,
}


sig SharedLinkSettingsAddPasswordType {
  description: String,
}


sig UndoOrganizeFolderWithTidyType {
  description: String,
}


sig UpdateFolderPolicyArg {
  viewer_info_policy: lone ViewerInfoPolicy,
  shared_link_policy: lone SharedLinkPolicy,
  shared_folder_id: SharedFolderId,
  acl_update_policy: lone AclUpdatePolicy,
  link_settings: lone LinkSettings,
  actions: lone set FolderAction,
  member_policy: lone MemberPolicy,
}


sig LinkPassword {
  .tag: String,
}


sig GroupsMembersListResult {
  has_more: Bool,
  members: set GroupMemberInfo,
  cursor: String,
}


sig TeamMergeRequestSentShownToPrimaryTeamDetails {
  sent_to: String,
  secondary_team: String,
}


sig CreateFileRequestArgs {
  title: String,
  destination: Path,
  description: lone String,
  open: Bool,
  deadline: lone FileRequestDeadline,
}


sig UploadSessionStartError {
  .tag: String,
}


sig FileMoveDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig TfaChangeStatusType {
  description: String,
}


sig AddTemplateArg {
  // Generic object with no specific type
}


sig SharedContentRemoveInviteesType {
  description: String,
}


sig DeviceApprovalsPolicy {
  .tag: String,
}


sig MembersGetAvailableTeamMemberRolesResult {
  roles: set TeamMemberRole,
}


sig BaseTagError {
  .tag: String,
}


sig UserSelectorArg {
  .tag: String,
}


sig AppLinkUserType {
  description: String,
}


sig LegalHoldsChangeHoldDetailsDetails {
  legal_hold_id: String,
  previous_value: String,
  new_value: String,
  name: String,
}


sig InviteAcceptanceEmailPolicy {
  .tag: String,
}


sig SearchMatchV2 {
  match_type: lone SearchMatchTypeV2,
  highlight_spans: lone set HighlightSpan,
  metadata: MetadataV2,
}


sig SharedFolderMemberError {
  .tag: String,
}


sig GroupDeleteDetails {
  is_company_managed: lone Bool,
}


sig MobileSessionLogInfo {
  // Generic object with no specific type
}


sig PaperEnabledUsersGroupRemovalDetails {
}


sig TokenFromOAuth1Result {
  oauth2_token: String,
}


sig NoteShareReceiveType {
  description: String,
}


sig SharedLinkCreateDetails {
  shared_link_access_level: lone SharedLinkAccessLevel,
}


sig PaperEnabledUsersGroupAdditionType {
  description: String,
}


sig TfaChangeStatusDetails {
  used_rescue_code: lone Bool,
  new_value: TfaConfiguration,
  previous_value: lone TfaConfiguration,
}


sig SharedLinkAccessLevel {
  .tag: String,
}


sig TeamFolderRenameArg {
  // Generic object with no specific type
}


sig AddTagArg {
  tag_text: TagText,
  path: Path,
}


sig LinkMetadata {
  url: String,
  expires: lone DropboxTimestamp,
  visibility: Visibility,
}


sig GroupMemberSelector {
  user: UserSelectorArg,
  group: GroupSelector,
}


sig LegalHoldsExportDownloadedDetails {
  export_name: String,
  name: String,
  part: lone String,
  legal_hold_id: String,
  file_name: lone String,
}


sig SearchV2Result {
  has_more: Bool,
  matches: set SearchMatchV2,
  cursor: lone SearchV2Cursor,
}


sig SfTeamUninviteDetails {
  original_folder_name: String,
  target_asset_index: Int,
}


sig GetTeamEventsContinueError {
  .tag: String,
}


sig GovernancePolicyEditDurationDetails {
  new_value: DurationLogInfo,
  policy_type: lone PolicyType,
  previous_value: DurationLogInfo,
  name: String,
  governance_policy_id: String,
}


sig TeamProfileChangeNameDetails {
  previous_value: lone TeamName,
  new_value: TeamName,
}


sig DomainInvitesApproveRequestToJoinTeamType {
  description: String,
}


sig MemberDeleteProfilePhotoType {
  description: String,
}


sig PaperPublishedLinkCreateType {
  description: String,
}


sig PathRootError {
  .tag: String,
}


sig ResellerSupportSessionStartDetails {
}


sig ExtendedVersionHistoryChangePolicyType {
  description: String,
}


sig DeviceChangeIpMobileType {
  description: String,
}


sig FolderAction {
  .tag: String,
}


sig PaperContentAddToFolderType {
  description: String,
}


sig ResellerId {
  // Primitive type: string
  value: String
}


sig FileRequestId {
  // Primitive type: string
  value: String
}


sig SharedLink {
  url: SharedLinkUrl,
  password: lone String,
}


sig GetFileRequestArgs {
  id: FileRequestId,
}


sig TeamEncryptionKeyDeleteKeyDetails {
}


sig PaperDocChangeSubscriptionDetails {
  new_subscription_level: String,
  event_uuid: String,
  previous_subscription_level: lone String,
}


sig ShowcaseEditedDetails {
  event_uuid: String,
}


sig ShowcaseUnresolveCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig MembersAddJobStatusV2Result {
  .tag: String,
}


sig MobileClientSession {
  // Generic object with no specific type
}


sig PaperAdminExportStartType {
  description: String,
}


sig SsoPolicy {
  .tag: String,
}


sig FileSharingInfo {
  // Generic object with no specific type
}


sig UserDeleteResult {
  .tag: String,
}


sig FolderLinkRestrictionPolicy {
  .tag: String,
}


sig LogicalOperator {
  .tag: String,
}


sig DesktopDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig NamespaceType {
  .tag: String,
}


sig BackupInvitationOpenedDetails {
}


sig DispositionActionType {
  .tag: String,
}


sig MembersSetPermissionsResult {
  team_member_id: TeamMemberId,
  role: AdminTier,
}


sig DeviceApprovalsAddExceptionType {
  description: String,
}


sig GroupSelectorWithTeamGroupError {
  .tag: String,
}


sig SharedLinkSettingsChangeAudienceDetails {
  previous_value: lone LinkAudience,
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
  new_value: LinkAudience,
}


sig AudienceExceptionContentInfo {
  name: String,
}


sig FolderOverviewItemUnpinnedDetails {
  folder_overview_location_asset: Int,
  pinned_items_asset_indices: set Int,
}


sig LegalHoldsExportAHoldDetails {
  name: String,
  export_name: lone String,
  legal_hold_id: String,
}


sig GroupDescriptionUpdatedType {
  description: String,
}


sig GetTeamEventsResult {
  events: set TeamEvent,
  cursor: String,
  has_more: Bool,
}


sig TeamFolderArchiveError {
  .tag: String,
}


sig HasTeamSelectiveSyncValue {
  .tag: String,
}


sig WritePath {
  // Primitive type: string
  value: String
}


sig ShowcasePostCommentType {
  description: String,
}


sig RewindFolderDetails {
  rewind_folder_target_ts_ms: DropboxTimestamp,
}


sig WebSessionsChangeIdleLengthPolicyType {
  description: String,
}


sig SaveUrlArg {
  path: Path,
  url: String,
}


sig GuestAdminChangeStatusDetails {
  host_team_name: lone String,
  previous_value: TrustedTeamsRequestState,
  guest_team_name: lone String,
  new_value: TrustedTeamsRequestState,
  action_details: TrustedTeamsRequestAction,
  is_guest: Bool,
}


sig LegalHoldsExportDownloadedType {
  description: String,
}


sig SharedLinkSettingsAllowDownloadDisabledType {
  description: String,
}


sig OptionalNamePart {
  // Primitive type: string
  value: String
}


sig PaperDocRequestAccessType {
  description: String,
}


sig NoPasswordLinkViewCreateReportDetails {
  start_date: DropboxTimestamp,
  end_date: DropboxTimestamp,
}


sig PaperDocChangeMemberRoleType {
  description: String,
}


sig PaperExternalViewDefaultTeamType {
  description: String,
}


sig SharedLinkAlreadyExistsMetadata {
  .tag: String,
}


sig TeamFolderListContinueError {
  .tag: String,
}


sig ShmodelGroupShareType {
  description: String,
}


sig PaperDocRevertDetails {
  event_uuid: String,
}


sig LegalHoldsListHeldRevisionResult {
  entries: set LegalHoldHeldRevisionMetadata,
  cursor: lone ListHeldRevisionCursor,
  has_more: Bool,
}


sig Rev {
  // Generic object with no specific type
}


sig ListPaperDocsSortOrder {
  .tag: String,
}


sig UserQuota {
  // Primitive type: integer
  value: Int
}


sig GovernancePolicyAddFoldersDetails {
  governance_policy_id: String,
  folders: lone set String,
  name: String,
  policy_type: lone PolicyType,
}


sig FileRollbackChangesType {
  description: String,
}


sig SharingChangeLinkDefaultExpirationPolicyType {
  description: String,
}


sig MalformedPathError {
  // Primitive type: string
  value: String
}


sig GroupMemberSetAccessTypeError {
  .tag: String,
}


sig LinkAccessLevel {
  .tag: String,
}


sig LegalHoldsPolicyReleaseArg {
  id: LegalHoldId,
}


sig PaperDefaultFolderPolicyChangedType {
  description: String,
}


sig ReplayFileSharedLinkModifiedDetails {
}


sig FolderPolicy {
  resolved_member_policy: lone MemberPolicy,
  member_policy: lone MemberPolicy,
  viewer_info_policy: lone ViewerInfoPolicy,
  acl_update_policy: AclUpdatePolicy,
  shared_link_policy: SharedLinkPolicy,
}


sig SharedContentRequestAccessType {
  description: String,
}


sig SharingChangeMemberPolicyDetails {
  previous_value: lone SharingMemberPolicy,
  new_value: SharingMemberPolicy,
}


sig MembersTransferFilesError {
  .tag: String,
}


sig SharedContentCopyDetails {
  shared_content_link: String,
  shared_content_access_level: AccessLevel,
  shared_content_owner: lone UserLogInfo,
  destination_path: FilePath,
}


sig UploadSessionStartArg {
  content_hash: lone Sha256HexHash,
  close: Bool,
  session_type: lone UploadSessionType,
}


sig MemberStatus {
  .tag: String,
}


sig MoveIntoVaultError {
  .tag: String,
}


sig LinkExpiry {
  .tag: String,
}


sig MembersRemoveError {
  .tag: String,
}


sig GuestAdminSignedOutViaTrustedTeamsType {
  description: String,
}


sig FileLock {
  content: FileLockContent,
}


sig TeamMergeRequestAcceptedShownToPrimaryTeamType {
  description: String,
}


sig EmmAddExceptionType {
  description: String,
}


sig GetTemporaryLinkArg {
  path: ReadPath,
}


sig PathLogInfo {
  namespace_relative: NamespaceRelativePathLogInfo,
  contextual: lone FilePath,
}


sig CreateFolderDetails {
}


sig ShowcaseRestoredDetails {
  event_uuid: String,
}


sig PaperPublishedLinkChangePermissionDetails {
  event_uuid: String,
  new_permission_level: String,
  previous_permission_level: String,
}


sig SharedContentChangeMemberRoleDetails {
  previous_access_level: lone AccessLevel,
  new_access_level: AccessLevel,
}


sig TeamBrandingPolicyChangedDetails {
  previous_value: TeamBrandingPolicy,
  new_value: TeamBrandingPolicy,
}


sig TeamFolderActivateError {
  .tag: String,
}


sig BinderReorderSectionType {
  description: String,
}


sig TeamEvent {
  event_category: EventCategory,
  origin: lone OriginLogInfo,
  involve_non_team_member: lone Bool,
  assets: lone set AssetLogInfo,
  details: EventDetails,
  timestamp: DropboxTimestamp,
  participants: lone set ParticipantLogInfo,
  context: lone ContextLogInfo,
  event_type: EventType,
  actor: lone ActorLogInfo,
}


sig SharedLinkFileInfo {
  path: lone String,
  password: lone String,
  url: String,
}


sig GetCopyReferenceArg {
  path: ReadPath,
}


sig CreateTeamInviteLinkType {
  description: String,
}


sig MemberChangeResellerRoleDetails {
  previous_value: ResellerRole,
  new_value: ResellerRole,
}


sig EmmCreateExceptionsReportDetails {
}


sig AdminConsoleAppPermission {
  .tag: String,
}


sig SendForSignaturePolicyChangedType {
  description: String,
}


sig ThumbnailV2Arg {
  resource: PathOrLink,
  format: ThumbnailFormat,
  size: ThumbnailSize,
  mode: ThumbnailMode,
}


sig NoExpirationLinkGenReportFailedType {
  description: String,
}


sig EmmRefreshAuthTokenType {
  description: String,
}


sig GroupAddMemberDetails {
  is_group_owner: Bool,
}


sig FileRequestChangeType {
  description: String,
}


sig LoginSuccessType {
  description: String,
}


sig SharedFolderMetadataBase {
  path_lower: lone String,
  is_inside_team_folder: Bool,
  owner_display_names: lone set String,
  is_team_folder: Bool,
  owner_team: lone Team,
  access_type: AccessLevel,
  parent_shared_folder_id: lone SharedFolderId,
  path_display: lone String,
  parent_folder_name: lone String,
}


sig TeamNamespacesListArg {
  limit: Int,
}


sig ListHeldRevisionCursor {
  // Primitive type: string
  value: String
}


sig BinderRenamePageDetails {
  doc_title: String,
  binder_item_name: String,
  previous_binder_item_name: lone String,
  event_uuid: String,
}


sig FileOpsResult {
}


sig TeamFolderArchiveLaunch {
  .tag: String,
}


sig ListPaperDocsContinueArgs {
  cursor: String,
}


sig GuestAdminSignedOutViaTrustedTeamsDetails {
  team_name: lone String,
  trusted_team_name: lone String,
}


sig SharedContentLinkMetadataBase {
  audience_options: set LinkAudience,
  audience_restricting_shared_folder: lone AudienceRestrictingSharedFolder,
  current_audience: LinkAudience,
  expiry: lone DropboxTimestamp,
  link_permissions: set LinkPermission,
  password_protected: Bool,
  access_level: lone AccessLevel,
}


sig ClassificationCreateReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig SsoChangePolicyType {
  description: String,
}


sig TeamProfileChangeNameType {
  description: String,
}


sig DomainVerificationAddDomainSuccessDetails {
  domain_names: set String,
  verification_method: lone String,
}


sig EmmAddExceptionDetails {
}


sig DownloadZipError {
  .tag: String,
}


sig ExpectedSharedContentLinkMetadata {
  // Generic object with no specific type
}


sig TeamMemberProfile {
  // Generic object with no specific type
}


sig DeviceLinkSuccessDetails {
  device_session_info: lone DeviceSessionLogInfo,
}


sig TeamProfileRemoveBackgroundDetails {
}


sig MemberAccess {
  access_type: GroupAccessType,
  user: UserSelectorArg,
}


sig MemberTransferAccountContentsType {
  description: String,
}


sig PaperExternalViewForbidType {
  description: String,
}


sig ListTeamAppsArg {
  cursor: lone String,
}


sig DeviceChangeIpDesktopType {
  description: String,
}


sig ListTeamAppsResult {
  has_more: Bool,
  apps: set MemberLinkedApps,
  cursor: lone String,
}


sig PaperDocChangeMemberRoleDetails {
  access_type: PaperAccessType,
  event_uuid: String,
}


sig TeamMergeRequestRevokedType {
  description: String,
}


sig Tag {
  .tag: String,
}


sig ListFileMembersCountResult {
  members: SharedFileMembers,
  member_count: Int,
}


sig GetMetadataArg {
  include_deleted: Bool,
  include_has_explicit_shared_members: Bool,
  path: ReadPath,
  include_media_info: Bool,
  include_property_groups: lone TemplateFilterBase,
}


sig BinderReorderPageDetails {
  doc_title: String,
  event_uuid: String,
  binder_item_name: String,
}


sig TeamMemberPolicies {
  emm_state: EmmState,
  office_addin: OfficeAddInPolicy,
  sharing: TeamSharingPolicies,
  suggest_members_policy: SuggestMembersPolicy,
}


sig FileTransfersPolicyChangedDetails {
  new_value: FileTransfersPolicy,
  previous_value: FileTransfersPolicy,
}


sig TfaAddBackupPhoneDetails {
}


sig UploadSessionAppendArg {
  content_hash: lone Sha256HexHash,
  cursor: UploadSessionCursor,
  close: Bool,
}


sig DropboxPasswordsExportedDetails {
  platform: String,
}


sig PaperExternalViewForbidDetails {
  event_uuid: String,
}


sig SfTeamInviteDetails {
  target_asset_index: Int,
  original_folder_name: String,
  sharing_permission: lone String,
}


sig ShowcaseArchivedDetails {
  event_uuid: String,
}


sig DownloadArg {
  path: ReadPath,
  rev: lone Rev,
}


sig PaperDocTrashedDetails {
  event_uuid: String,
}


sig GovernancePolicyExportCreatedType {
  description: String,
}


sig PaperContentArchiveDetails {
  event_uuid: String,
}


sig MemberAddExternalIdType {
  description: String,
}


sig SecondaryMailsPolicy {
  .tag: String,
}


sig TeamInfo {
  // Generic object with no specific type
}


sig MembersSetProfilePhotoArg {
  photo: PhotoSourceArg,
  user: UserSelectorArg,
}


sig PhotoSourceArg {
  .tag: String,
}


sig LegalHoldsPolicyUpdateError {
  .tag: String,
}


sig ListMemberAppsResult {
  linked_api_apps: set ApiApp,
}


sig GroupJoinPolicyUpdatedDetails {
  is_company_managed: lone Bool,
  join_policy: lone GroupJoinPolicy,
}


sig GroupMembersRemoveError {
  .tag: String,
}


sig ShowcaseDeleteCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig TeamMergeRequestAcceptedType {
  description: String,
}


sig ShowcaseFileRemovedDetails {
  event_uuid: String,
}


sig ExcludedUsersListContinueArg {
  cursor: String,
}


sig GoogleSsoChangePolicyType {
  description: String,
}


sig PaperFolderChangeSubscriptionType {
  description: String,
}


sig TfaResetType {
  description: String,
}


sig SmartSyncPolicy {
  .tag: String,
}


sig ExportMembersReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig DeviceType {
  .tag: String,
}


sig GroupsListResult {
  groups: set GroupSummary,
  has_more: Bool,
  cursor: String,
}


sig TeamFolderUpdateSyncSettingsArg {
  // Generic object with no specific type
}


sig AdminAlertingAlertConfiguration {
  text: lone String,
  alert_state: lone AdminAlertingAlertStatePolicy,
  sensitivity_level: lone AdminAlertingAlertSensitivity,
  excluded_file_extensions: lone String,
  recipients_settings: lone RecipientsConfiguration,
}


sig TeamProfileAddLogoType {
  description: String,
}


sig BinderReorderPageType {
  description: String,
}


sig MemberAddArg {
  // Generic object with no specific type
}


sig SharedContentChangeLinkAudienceType {
  description: String,
}


sig PreviewError {
  .tag: String,
}


sig RelocationBatchV2JobStatus {
  .tag: String,
}


sig ReplayFileSharedLinkCreatedDetails {
}


sig ReplayFileSharedLinkCreatedType {
  description: String,
}


sig DataPlacementRestrictionChangePolicyDetails {
  previous_value: PlacementRestriction,
  new_value: PlacementRestriction,
}


sig FileMoveType {
  description: String,
}


sig ReplayProjectTeamAddType {
  description: String,
}


sig ShowcaseChangeDownloadPolicyType {
  description: String,
}


sig ResellerSupportPolicy {
  .tag: String,
}


sig SharedContentViewDetails {
  shared_content_link: String,
  shared_content_owner: lone UserLogInfo,
  shared_content_access_level: AccessLevel,
}


sig AppId {
  // Primitive type: string
  value: String
}


sig SearchV2ContinueArg {
  cursor: SearchV2Cursor,
}


sig MembersAddLaunchV2Result {
  .tag: String,
}


sig FileCommentsPolicy {
  .tag: String,
}


sig EventCategory {
  .tag: String,
}


sig DeviceManagementEnabledDetails {
}


sig GroupMembersSelectorError {
  .tag: String,
}


sig LinkAction {
  .tag: String,
}


sig ListMemberDevicesArg {
  team_member_id: String,
  include_web_sessions: Bool,
  include_mobile_clients: Bool,
  include_desktop_clients: Bool,
}


sig TfaRemoveExceptionType {
  description: String,
}


sig ShowcaseFileViewDetails {
  event_uuid: String,
}


sig PaperPublishedLinkChangePermissionType {
  description: String,
}


sig DeviceSession {
  country: lone String,
  ip_address: lone String,
  updated: lone DropboxTimestamp,
  created: lone DropboxTimestamp,
  session_id: String,
}


sig PaperDocRevertType {
  description: String,
}


sig SfFbUninviteType {
  description: String,
}


sig ListSharedLinksResult {
  links: set SharedLinkMetadata,
  has_more: Bool,
  cursor: lone String,
}


sig PollEmptyResult {
  .tag: String,
}


sig RevokeDeviceSessionStatus {
  success: Bool,
  error_type: lone RevokeDeviceSessionError,
}


sig DownloadZipResult {
  metadata: FolderMetadata,
}


sig TeamFolderAccessError {
  .tag: String,
}


sig AudienceExceptions {
  count: Int,
  exceptions: set AudienceExceptionContentInfo,
}


sig AdminAlertingAlertStateChangedType {
  description: String,
}


sig PropertiesSearchQuery {
  mode: PropertiesSearchMode,
  logical_operator: LogicalOperator,
  query: String,
}


sig TeamSpaceAllocation {
  used: Int,
  user_within_team_space_used_cached: Int,
  user_within_team_space_allocated: Int,
  allocated: Int,
  user_within_team_space_limit_type: MemberSpaceLimitType,
}


sig GovernancePolicyReportCreatedDetails {
  policy_type: lone PolicyType,
  governance_policy_id: String,
  name: String,
}


sig TeamActivityCreateReportDetails {
  end_date: DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig TeamMergeRequestRejectedShownToSecondaryTeamDetails {
  sent_by: String,
}


sig ExtendedVersionHistoryPolicy {
  .tag: String,
}


sig MembersSetPermissionsArg {
  new_role: AdminTier,
  user: UserSelectorArg,
}


sig MembersSendWelcomeError {
  .tag: String,
}


sig Metadata {
  preview_url: lone String,
  name: String,
  path_display: lone String,
  parent_shared_folder_id: lone SharedFolderId,
  path_lower: lone String,
}


sig PaperDocUpdateArgs {
  // Generic object with no specific type
}


sig MemberSendInvitePolicyChangedDetails {
  previous_value: MemberSendInvitePolicy,
  new_value: MemberSendInvitePolicy,
}


sig SharedContentChangeDownloadsPolicyDetails {
  previous_value: lone DownloadPolicyType,
  new_value: DownloadPolicyType,
}


sig TfaChangeBackupPhoneType {
  description: String,
}


sig CameraUploadsPolicy {
  .tag: String,
}


sig ThumbnailArg {
  size: ThumbnailSize,
  path: ReadPath,
  mode: ThumbnailMode,
  format: ThumbnailFormat,
}


sig ShareFolderErrorBase {
  .tag: String,
}


sig SharingChangeMemberPolicyType {
  description: String,
}


sig ViewerInfoPolicyChangedDetails {
  previous_value: PassPolicy,
  new_value: PassPolicy,
}


sig PaperPublishedLinkViewDetails {
  event_uuid: String,
}


sig TeamMergeRequestExpiredDetails {
  request_expired_details: TeamMergeRequestExpiredExtraDetails,
}


sig UploadWriteFailed {
  reason: WriteError,
  upload_session_id: String,
}


sig AdminAlertingTriggeredAlertType {
  description: String,
}


sig NoExpirationLinkGenCreateReportType {
  description: String,
}


sig NamespaceMetadata {
  namespace_id: SharedFolderId,
  name: String,
  namespace_type: NamespaceType,
  team_member_id: lone TeamMemberId,
}


sig Dimensions {
  height: Int,
  width: Int,
}


sig CreateFolderBatchLaunch {
  .tag: String,
}


sig TeamName {
  team_display_name: String,
  team_legal_name: String,
}


sig SharedContentChangeLinkExpiryDetails {
  new_value: lone DropboxTimestamp,
  previous_value: lone DropboxTimestamp,
}


sig DeleteFileRequestError {
  .tag: String,
}


sig FileRevertType {
  description: String,
}


sig SearchError {
  .tag: String,
}


sig FileErrorResult {
  .tag: String,
}


sig TemplateError {
  .tag: String,
}


sig ThumbnailError {
  .tag: String,
}


sig NoPasswordLinkGenReportFailedType {
  description: String,
}


sig FilePreviewDetails {
}


sig ListFileMembersIndividualResult {
  .tag: String,
}


sig PaperDocUntrashedDetails {
  event_uuid: String,
}


sig PaperEnabledPolicy {
  .tag: String,
}


sig ShowcaseExternalSharingPolicy {
  .tag: String,
}


sig PathROrId {
  // Primitive type: string
  value: String
}


sig PrimaryTeamRequestReminderDetails {
  sent_to: String,
  secondary_team: String,
}


sig AddMemberSelectorError {
  .tag: String,
}


sig GroupAddExternalIdDetails {
  new_value: GroupExternalId,
}


sig ShareFolderJobStatus {
  .tag: String,
}


sig SharedFolderCreateDetails {
  target_ns_id: lone NamespaceId,
}


sig CameraUploadsPolicyChangedDetails {
  new_value: CameraUploadsPolicy,
  previous_value: CameraUploadsPolicy,
}


sig BinderRenameSectionDetails {
  binder_item_name: String,
  previous_binder_item_name: lone String,
  event_uuid: String,
  doc_title: String,
}


sig PaperDocCreateArgs {
  parent_folder_id: lone String,
  import_format: ImportFormat,
}


sig SsoChangeSamlIdentityModeDetails {
  new_value: Int,
  previous_value: Int,
}


sig SpaceUsage {
  allocation: SpaceAllocation,
  used: Int,
}


sig SpaceLimitsStatus {
  .tag: String,
}


sig FileResolveCommentType {
  description: String,
}


sig PaperContentError {
  .tag: String,
}


sig FileUnlikeCommentType {
  description: String,
}


sig LoginFailDetails {
  login_method: LoginMethod,
  error_details: FailureDetailsLogInfo,
  is_emm_managed: lone Bool,
}


sig MemberRequestsChangePolicyType {
  description: String,
}


sig ListTeamDevicesResult {
  devices: set MemberDevices,
  has_more: Bool,
  cursor: lone String,
}


sig GetTagsArg {
  paths: set Path,
}


sig ShowcaseFileAddedType {
  description: String,
}


sig UserResendEmailsResult {
  user: UserSelectorArg,
  results: set ResendSecondaryEmailResult,
}


sig ReplayFileDeleteDetails {
}


sig ShowcaseChangeEnabledPolicyType {
  description: String,
}


sig CollectionLinkMetadata {
  // Generic object with no specific type
}


sig ListFolderResult {
  cursor: ListFolderCursor,
  entries: set Metadata,
  has_more: Bool,
}


sig MemberAccessLevelResult {
  access_level: lone AccessLevel,
  warning: lone String,
  access_details: lone set ParentFolderAccessInfo,
}


sig BinderAddSectionType {
  description: String,
}


sig SaveCopyReferenceResult {
  metadata: Metadata,
}


sig SecondaryMailsPolicyChangedDetails {
  previous_value: SecondaryMailsPolicy,
  new_value: SecondaryMailsPolicy,
}


sig FileLockingValue {
  .tag: String,
}


sig GroupsListContinueArg {
  cursor: String,
}


sig GuestAdminSignedInViaTrustedTeamsType {
  description: String,
}


sig TeamProfileChangeLogoDetails {
}


sig TeamMergeRequestReminderDetails {
  request_reminder_details: TeamMergeRequestReminderExtraDetails,
}


sig TeamFolderMetadata {
  status: TeamFolderStatus,
  team_folder_id: SharedFolderId,
  name: String,
  content_sync_settings: set ContentSyncSetting,
  sync_setting: SyncSetting,
  is_team_shared_dropbox: Bool,
}


sig SharedLinkSettingsRemovePasswordType {
  description: String,
}


sig RansomwareRestoreProcessStartedDetails {
  extension: String,
}


sig IndividualSpaceAllocation {
  allocated: Int,
}


sig MemberChangeEmailDetails {
  new_value: EmailAddress,
  previous_value: lone EmailAddress,
}


sig DeviceSyncBackupStatusChangedType {
  description: String,
}


sig MemberChangeMembershipTypeType {
  description: String,
}


sig UpdateFileRequestArgs {
  destination: lone Path,
  open: lone Bool,
  title: lone String,
  id: FileRequestId,
  description: lone String,
  deadline: UpdateFileRequestDeadline,
}


sig DomainInvitesSetInviteNewUserPrefToNoDetails {
}


sig QuickActionType {
  .tag: String,
}


sig PaperDocExportResult {
  owner: String,
  title: String,
  mime_type: String,
  revision: Int,
}


sig GeneralFileRequestsError {
  .tag: String,
}


sig TeamInviteDetails {
  invite_method: InviteMethod,
  additional_license_purchase: lone Bool,
}


sig GroupLogInfo {
  group_id: lone GroupId,
  display_name: String,
  external_id: lone GroupExternalId,
}


sig TeamMergeRequestReminderShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_to: String,
}


sig FedAdminRole {
  .tag: String,
}


sig ShowcaseCreatedType {
  description: String,
}


sig WatermarkingPolicyChangedType {
  description: String,
}


sig SsoAddCertType {
  description: String,
}


sig SharingMemberPolicy {
  .tag: String,
}


sig ShmodelDisableDownloadsType {
  description: String,
}


sig SharingChangeLinkDefaultExpirationPolicyDetails {
  previous_value: lone DefaultLinkExpirationDaysPolicy,
  new_value: DefaultLinkExpirationDaysPolicy,
}


sig ShowcasePostCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig DeviceChangeIpWebType {
  description: String,
}


sig CreateFolderBatchJobStatus {
  .tag: String,
}


sig ShowcaseChangeExternalSharingPolicyType {
  description: String,
}


sig MembersSetProfileArg {
  new_email: lone EmailAddress,
  new_external_id: lone MemberExternalId,
  new_is_directory_restricted: lone Bool,
  new_given_name: lone OptionalNamePart,
  new_surname: lone OptionalNamePart,
  new_persistent_id: lone String,
  user: UserSelectorArg,
}


sig PropertyGroup {
  template_id: TemplateId,
  fields: set PropertyField,
}


sig SharedFolderAccessError {
  .tag: String,
}


sig ExcludedUsersUpdateStatus {
  .tag: String,
}


sig PaperApiCursorError {
  .tag: String,
}


sig UserNameLogInfo {
  given_name: String,
  surname: String,
  locale: lone String,
}


sig SfAddGroupDetails {
  original_folder_name: String,
  target_asset_index: Int,
  sharing_permission: lone String,
  team_name: String,
}


sig FileTransfersPolicy {
  .tag: String,
}


sig AlphaResolvedVisibility {
  .tag: String,
}


sig SfTeamJoinFromOobLinkType {
  description: String,
}


sig RevokeDeviceSessionError {
  .tag: String,
}


sig PlatformType {
  .tag: String,
}


sig SpaceAllocation {
  .tag: String,
}


sig MembersRecoverArg {
  user: UserSelectorArg,
}


sig SessionId {
  // Primitive type: string
  value: String
}


sig SharedLinkShareType {
  description: String,
}


sig PaperDocCreateUpdateResult {
  doc_id: String,
  revision: Int,
  title: String,
}


sig PaperDocEditType {
  description: String,
}


sig SuggestMembersPolicy {
  .tag: String,
}


sig TeamEventList {
  items: set TeamEvent
}


sig AccessError {
  .tag: String,
}


sig PropertyFieldTemplate {
  name: String,
  type: PropertyType,
  description: String,
}


sig TrustedNonTeamMemberType {
  .tag: String,
}


sig OverwritePropertyGroupArg {
  property_groups: set PropertyGroup,
  path: PathOrId,
}


sig MembersInfo {
  permanently_deleted_users: Int,
  team_member_ids: set TeamMemberId,
}


sig SharedLinkDisableDetails {
  shared_link_owner: lone UserLogInfo,
}


sig TfaRemoveSecurityKeyType {
  description: String,
}


sig PaperContentCreateType {
  description: String,
}


sig MemberRequestsPolicy {
  .tag: String,
}


sig MembersGetInfoItemV2 {
  .tag: String,
}


sig ShareFolderArgBase {
  force_async: Bool,
  member_policy: lone MemberPolicy,
  path: WritePathOrId,
  shared_link_policy: lone SharedLinkPolicy,
  access_inheritance: AccessInheritance,
  acl_update_policy: lone AclUpdatePolicy,
  viewer_info_policy: lone ViewerInfoPolicy,
}


sig SsoErrorType {
  description: String,
}


sig SsoChangeSamlIdentityModeType {
  description: String,
}


sig SharedLinkSettingsAllowDownloadEnabledType {
  description: String,
}


sig FolderLinkRestrictionPolicyChangedDetails {
  previous_value: FolderLinkRestrictionPolicy,
  new_value: FolderLinkRestrictionPolicy,
}


sig AllowDownloadDisabledDetails {
}


sig EmmErrorType {
  description: String,
}


sig ResolvedVisibility {
  .tag: String,
}


sig PathRoot {
  .tag: String,
}


sig TeamProfileAddBackgroundType {
  description: String,
}


sig DefaultLinkExpirationDaysPolicy {
  .tag: String,
}


sig ExternalSharingReportFailedType {
  description: String,
}


sig AppUnlinkTeamDetails {
  app_info: AppLogInfo,
}


sig TeamEncryptionKeyDisableKeyDetails {
}


sig MobileClientPlatform {
  .tag: String,
}


sig TeamMergeRequestReminderShownToPrimaryTeamType {
  description: String,
}


sig TeamMemberRole {
  name: String,
  role_id: TeamMemberRoleId,
  description: String,
}


sig UnmountFolderArg {
  shared_folder_id: SharedFolderId,
}


sig GovernancePolicyDeleteType {
  description: String,
}


sig BinderRemovePageDetails {
  binder_item_name: String,
  doc_title: String,
  event_uuid: String,
}


sig UserSelectorError {
  .tag: String,
}


sig Account {
  profile_photo_url: lone String,
  account_id: AccountId,
  email_verified: Bool,
  name: Name,
  email: String,
  disabled: Bool,
}


sig TeamMergeRequestReminderShownToSecondaryTeamType {
  description: String,
}


sig GetSharedLinkFileArg {
  // Generic object with no specific type
}


sig TeamMergeRequestRejectedShownToSecondaryTeamType {
  description: String,
}


sig TeamDetails {
  team: String,
}


sig TeamMergeToDetails {
  team_name: String,
}


sig DeviceApprovalsChangeOverageActionType {
  description: String,
}


sig PaperChangeDeploymentPolicyDetails {
  new_value: PaperDeploymentPolicy,
  previous_value: lone PaperDeploymentPolicy,
}


sig LegalHoldsListHeldRevisionsError {
  .tag: String,
}


sig AdminTier {
  .tag: String,
}


sig ShowcaseArchivedType {
  description: String,
}


sig PropertyField {
  name: String,
  value: String,
}


sig RelocationBatchV2Result {
  // Generic object with no specific type
}


sig FileLockingLockStatusChangedDetails {
  previous_value: LockStatus,
  new_value: LockStatus,
}


sig SharedLinkSettingsAllowDownloadDisabledDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
}


sig SsoRemoveCertType {
  description: String,
}


sig SharingAllowlistRemoveResponse {
}


sig GroupMembersRemoveArg {
  // Generic object with no specific type
}


sig FileRequestCreateType {
  description: String,
}


sig SharedLinkSettingsRemoveExpirationType {
  description: String,
}


sig ShareFolderError {
  .tag: String,
}


sig ParticipantLogInfo {
  .tag: String,
}


sig PaperDefaultFolderPolicyChangedDetails {
  previous_value: PaperDefaultFolderPolicy,
  new_value: PaperDefaultFolderPolicy,
}


sig ResellerLogInfo {
  reseller_name: String,
  reseller_email: EmailAddress,
}


sig ListPaperDocsResponse {
  cursor: Cursor,
  has_more: Bool,
  doc_ids: set PaperDocId,
}


sig PasswordResetType {
  description: String,
}


sig GroupsGetInfoError {
  .tag: String,
}


sig MemberSpaceLimitsChangePolicyType {
  description: String,
}


sig ReplayProjectTeamAddDetails {
}


sig SfFbInviteDetails {
  original_folder_name: String,
  sharing_permission: lone String,
  target_asset_index: Int,
}


sig GroupChangeMemberRoleType {
  description: String,
}


sig MemberSpaceLimitsChangePolicyDetails {
  previous_value: lone Int,
  new_value: lone Int,
}


sig DeviceSyncBackupStatusChangedDetails {
  previous_value: BackupStatus,
  new_value: BackupStatus,
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
}


sig FileRequestError {
  .tag: String,
}


sig MemberChangeEmailType {
  description: String,
}


sig NoteAclLinkType {
  description: String,
}


sig MembersAddLaunch {
  .tag: String,
}


sig DeviceChangeIpWebDetails {
  user_agent: String,
}


sig PropertiesSearchResult {
  matches: set PropertiesSearchMatch,
  cursor: lone PropertiesSearchCursor,
}


sig SharedFileMetadata {
  policy: FolderPolicy,
  preview_url: String,
  name: String,
  parent_shared_folder_id: lone SharedFolderId,
  time_invited: lone DropboxTimestamp,
  owner_display_names: lone set String,
  owner_team: lone Team,
  path_display: lone String,
  access_type: lone AccessLevel,
  id: FileId,
  link_metadata: lone SharedContentLinkMetadata,
  path_lower: lone String,
  expected_link_metadata: lone ExpectedSharedContentLinkMetadata,
  permissions: lone set FilePermission,
}


sig GetFileMetadataBatchResult {
  file: PathOrId,
  result: GetFileMetadataIndividualResult,
}


sig SharedFileMembers {
  invitees: set InviteeMembershipInfo,
  users: set UserFileMembershipInfo,
  cursor: lone String,
  groups: set GroupMembershipInfo,
}


sig SharedContentDownloadDetails {
  shared_content_owner: lone UserLogInfo,
  shared_content_link: String,
  shared_content_access_level: AccessLevel,
}


sig LegalHoldsChangeHoldNameType {
  description: String,
}


sig NoteSharedType {
  description: String,
}


sig TeamMemberInfo {
  profile: TeamMemberProfile,
  role: AdminTier,
}


sig MembersRecoverError {
  .tag: String,
}


sig FileTransfersTransferDeleteType {
  description: String,
}


sig FileRequestValidationError {
  // Primitive type: string
  value: String
}


sig SharedLinkSettingsChangeExpirationDetails {
  shared_content_link: lone String,
  previous_value: lone DropboxTimestamp,
  shared_content_access_level: AccessLevel,
  new_value: lone DropboxTimestamp,
}


sig GovernancePolicyRemoveFoldersType {
  description: String,
}


sig ListFilesResult {
  cursor: lone String,
  entries: set SharedFileMetadata,
}


sig AddSecondaryEmailsResult {
  results: set UserAddResult,
}


sig SharedFolderMetadata {
  // Generic object with no specific type
}


sig CaptureTranscriptPolicyChangedType {
  description: String,
}


sig MemberTransferAccountContentsDetails {
}


sig PaperDocViewDetails {
  event_uuid: String,
}


sig DomainInvitesRequestToJoinTeamDetails {
}


sig SsoAddLogoutUrlDetails {
  new_value: lone String,
}


sig TeamFolderDowngradeType {
  description: String,
}


sig DeviceApprovalsChangeOverageActionDetails {
  previous_value: lone RolloutMethod,
  new_value: lone RolloutMethod,
}


sig TokenScopeError {
  required_scope: String,
}


sig AccountCapturePolicy {
  .tag: String,
}


sig SecondaryEmailVerifiedDetails {
  secondary_email: EmailAddress,
}


sig RootInfo {
  root_namespace_id: NamespaceId,
  home_namespace_id: NamespaceId,
}


sig SharedFolderId {
  // Generic object with no specific type
}


sig CreateFolderResult {
  // Generic object with no specific type
}


sig BackupAdminInvitationSentDetails {
}


sig PaperChangePolicyDetails {
  new_value: PaperEnabledPolicy,
  previous_value: lone PaperEnabledPolicy,
}


sig DeviceApprovalsChangeDesktopPolicyDetails {
  previous_value: lone DeviceApprovalsPolicy,
  new_value: lone DeviceApprovalsPolicy,
}


sig TemplateFilter {
  .tag: String,
}


sig SharedLinkSettingsChangePasswordType {
  description: String,
}


sig PaperContentCreateDetails {
  event_uuid: String,
}


sig SyncSetting {
  .tag: String,
}


sig AlphaGetMetadataArg {
  // Generic object with no specific type
}


sig ListRevisionsResult {
  server_deleted: lone DropboxTimestamp,
  is_deleted: Bool,
  entries: set FileMetadata,
}


sig UserFileMembershipInfo {
  // Generic object with no specific type
}


sig NetworkControlChangePolicyType {
  description: String,
}


sig LegalHoldsPolicyUpdateResult {
  // Generic object with no specific type
}


sig GroupRemoveMemberDetails {
}


sig VideoMetadata {
  // Generic object with no specific type
}


sig PaperPublishedLinkDisabledDetails {
  event_uuid: String,
}


sig MembersListV2Result {
  members: set TeamMemberInfoV2,
  cursor: String,
  has_more: Bool,
}


sig GetThumbnailBatchArg {
  entries: set ThumbnailArg,
}


sig JoinTeamDetails {
  was_linked_shared_folders_truncated: lone Bool,
  has_linked_devices: lone Bool,
  linked_apps: set UserLinkedAppLogInfo,
  was_linked_apps_truncated: lone Bool,
  linked_devices: set LinkedDeviceLogInfo,
  has_linked_shared_folders: lone Bool,
  has_linked_apps: lone Bool,
  linked_shared_folders: set FolderLogInfo,
  was_linked_devices_truncated: lone Bool,
}


sig SecondaryTeamRequestCanceledDetails {
  sent_by: String,
  sent_to: String,
}


sig RemovedStatus {
  is_recoverable: Bool,
  is_disconnected: Bool,
}


sig LegalHoldsAddMembersDetails {
  name: String,
  legal_hold_id: String,
}


sig MemberChangeExternalIdType {
  description: String,
}


sig IntegrationPolicy {
  .tag: String,
}


sig DropboxPasswordsNewDeviceEnrolledDetails {
  is_first_device: Bool,
  platform: String,
}


sig PaperContentRestoreType {
  description: String,
}


sig SmarterSmartSyncPolicyChangedDetails {
  previous_value: SmarterSmartSyncPolicyState,
  new_value: SmarterSmartSyncPolicyState,
}


sig ListTeamDevicesError {
  .tag: String,
}


sig FileAddType {
  description: String,
}


sig BinderAddPageType {
  description: String,
}


sig ClassificationCreateReportType {
  description: String,
}


sig PaperContentRestoreDetails {
  event_uuid: String,
}


sig FileLockingPolicyChangedDetails {
  new_value: FileLockingPolicyState,
  previous_value: FileLockingPolicyState,
}


sig AccessMethodLogInfo {
  .tag: String,
}


sig DeviceDeleteOnUnlinkFailDetails {
  num_failures: Int,
  session_info: lone SessionLogInfo,
  display_name: lone String,
}


sig SharedLinkChangeVisibilityDetails {
  previous_value: lone SharedLinkVisibility,
  new_value: SharedLinkVisibility,
}


sig LegacyDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig PaperDocResolveCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig ListPaperDocsArgs {
  limit: Int,
  sort_order: ListPaperDocsSortOrder,
  sort_by: ListPaperDocsSortBy,
  filter_by: ListPaperDocsFilterBy,
}


sig FileRequestCreateDetails {
  file_request_id: lone FileRequestId,
  request_details: lone FileRequestDetails,
}


sig RansomwareAlertCreateReportType {
  description: String,
}


sig MemberSetProfilePhotoType {
  description: String,
}


sig FileRestoreType {
  description: String,
}


sig AccessLevel {
  .tag: String,
}


sig TeamMergeRequestCanceledShownToPrimaryTeamType {
  description: String,
}


sig LegalHoldsExportRemovedDetails {
  export_name: String,
  name: String,
  legal_hold_id: String,
}


sig TeamMergeRequestAcceptedExtraDetails {
  .tag: String,
}


sig GroupMovedType {
  description: String,
}


sig NonTeamMemberLogInfo {
  // Generic object with no specific type
}


sig SfInviteGroupDetails {
  target_asset_index: Int,
}


sig SharedContentChangeViewerInfoPolicyDetails {
  previous_value: lone ViewerInfoPolicy,
  new_value: ViewerInfoPolicy,
}


sig GroupJoinPolicy {
  .tag: String,
}


sig FileRenameType {
  description: String,
}


sig CreateFolderBatchArg {
  force_async: Bool,
  paths: set WritePath,
  autorename: Bool,
}


sig RecipientsConfiguration {
  emails: lone set EmailAddress,
  groups: lone set String,
  recipient_setting_type: lone AlertRecipientsSettingType,
}


sig GroupFullInfo {
  // Generic object with no specific type
}


sig GroupAccessType {
  .tag: String,
}


sig FolderMetadata {
  // Generic object with no specific type
}


sig LockConflictError {
  lock: FileLock,
}


sig SearchMatchTypeV2 {
  .tag: String,
}


sig SharedContentLinkMetadata {
  // Generic object with no specific type
}


sig EndedEnterpriseAdminSessionDeprecatedDetails {
  federation_extra_details: FedExtraDetails,
}


sig DeviceUnlinkType {
  description: String,
}


sig PassPolicy {
  .tag: String,
}


sig ShowcaseEnabledPolicy {
  .tag: String,
}


sig ShowcaseRemoveMemberType {
  description: String,
}


sig FileTransfersTransferViewType {
  description: String,
}


sig FolderPermission {
  action: FolderAction,
  allow: Bool,
  reason: lone PermissionDeniedReason,
}


sig EnabledDomainInvitesDetails {
}


sig UserInfoWithPermissionLevel {
  permission_level: PaperDocPermissionLevel,
  user: UserInfo,
}


sig ListPaperDocsFilterBy {
  .tag: String,
}


sig AddTemplateResult {
  template_id: TemplateId,
}


sig PaperDocDeletedDetails {
  event_uuid: String,
}


sig RevokeLinkedAppBatchError {
  .tag: String,
}


sig FileAddFromAutomationType {
  description: String,
}


sig PaperContentRenameType {
  description: String,
}


sig GetMetadataError {
  .tag: String,
}


sig EmmRemoveExceptionDetails {
}


sig TemplateOwnerType {
  .tag: String,
}


sig SpaceCapsType {
  .tag: String,
}


sig AccountId {
  // Primitive type: string
  value: String
}


sig TrustedTeamsRequestAction {
  .tag: String,
}


sig ExportFormat {
  .tag: String,
}


sig MembersGetInfoItem {
  .tag: String,
}


sig UnshareFileError {
  .tag: String,
}


sig MemberAction {
  .tag: String,
}


sig TeamFolderCreateType {
  description: String,
}


sig AdminEmailRemindersChangedType {
  description: String,
}


sig InvalidAccountTypeError {
  .tag: String,
}


sig SharedContentViewType {
  description: String,
}


sig AdminAlertCategoryEnum {
  .tag: String,
}


sig MemberAddArgBase {
  member_external_id: lone MemberExternalId,
  send_welcome_email: Bool,
  member_surname: lone OptionalNamePart,
  is_directory_restricted: lone Bool,
  member_persistent_id: lone String,
  member_email: EmailAddress,
  member_given_name: lone OptionalNamePart,
}


sig MemberChangeAdminRoleDetails {
  new_value: lone AdminRole,
  previous_value: lone AdminRole,
}


sig FileRequestsChangePolicyDetails {
  new_value: FileRequestsPolicy,
  previous_value: lone FileRequestsPolicy,
}


sig ExportMembersReportType {
  description: String,
}


sig TeamFolderTeamSharedDropboxError {
  .tag: String,
}


sig RefPaperDoc {
  doc_id: PaperDocId,
}


sig DeviceManagementDisabledDetails {
}


sig TeamNamespacesListContinueError {
  .tag: String,
}


sig LaunchEmptyResult {
  .tag: String,
}


sig PropertyGroupTemplate {
  fields: set PropertyFieldTemplate,
  name: String,
  description: String,
}


sig PasswordResetAllDetails {
}


sig SharedLinkUrl {
  // Primitive type: string
  value: String
}


sig UpdatePropertiesArg {
  path: PathOrId,
  update_property_groups: set PropertyGroupUpdate,
}


sig ShowcaseUnresolveCommentType {
  description: String,
}


sig DomainInvitesApproveRequestToJoinTeamDetails {
}


sig GroupRemoveMemberType {
  description: String,
}


sig AccountCaptureRelinquishAccountDetails {
  domain_name: String,
}


sig ObjectLabelRemovedDetails {
  label_type: LabelType,
}


sig BinderAddPageDetails {
  binder_item_name: String,
  event_uuid: String,
  doc_title: String,
}


sig GetTemporaryUploadLinkArg {
  commit_info: CommitInfo,
  duration: Int,
}


sig ResellerSupportChangePolicyType {
  description: String,
}


sig AddFileMemberError {
  .tag: String,
}


sig UserLogInfo {
  account_id: lone AccountId,
  email: lone EmailAddress,
  display_name: lone DisplayNameLegacy,
}


sig GovernancePolicyContentDisposedDetails {
  disposition_type: DispositionActionType,
  name: String,
  governance_policy_id: String,
  policy_type: lone PolicyType,
}


sig NoPasswordLinkViewReportFailedType {
  description: String,
}


sig ExcludedUsersListResult {
  has_more: Bool,
  users: set MemberProfile,
  cursor: lone String,
}


sig OrganizationDetails {
  organization: String,
}


sig TfaChangePolicyDetails {
  new_value: TwoStepVerificationPolicy,
  previous_value: lone TwoStepVerificationPolicy,
}


sig BinderRemoveSectionDetails {
  event_uuid: String,
  binder_item_name: String,
  doc_title: String,
}


sig PaperDocDownloadDetails {
  export_file_format: PaperDownloadFormat,
  event_uuid: String,
}


sig DomainInvitesEmailExistingUsersDetails {
  num_recipients: Int,
  domain_name: String,
}


sig GetTeamEventsContinueArg {
  cursor: String,
}


sig SharedFolderDeclineInvitationDetails {
}


sig LookUpPropertiesError {
  .tag: String,
}


sig MembersUnsuspendArg {
  user: UserSelectorArg,
}


sig MemberAddResultBase {
  .tag: String,
}


sig GetThumbnailBatchError {
  .tag: String,
}


sig SessionLogInfo {
  session_id: lone SessionId,
}


sig GovernancePolicyAddFolderFailedType {
  description: String,
}


sig GuestAdminChangeStatusType {
  description: String,
}


sig SharedFolderNestDetails {
  previous_ns_path: lone FilePath,
  new_ns_path: lone FilePath,
  previous_parent_ns_id: lone NamespaceId,
  new_parent_ns_id: lone NamespaceId,
}


sig ListFileRequestsContinueError {
  .tag: String,
}


sig UserDeleteEmailsResult {
  results: set DeleteSecondaryEmailResult,
  user: UserSelectorArg,
}


sig SsoChangePolicyDetails {
  new_value: SsoPolicy,
  previous_value: lone SsoPolicy,
}


sig TeamFolderRenameError {
  .tag: String,
}


sig TeamProfileRemoveLogoDetails {
}


sig PaperAsFilesValue {
  .tag: String,
}


sig UpdateTemplateArg {
  description: lone String,
  add_fields: lone set PropertyFieldTemplate,
  name: lone String,
  template_id: TemplateId,
}


sig FileDeleteType {
  description: String,
}


sig MemberSuggestionsChangePolicyType {
  description: String,
}


sig UserInfoArgs {
}


sig FileAddDetails {
}


sig ResellerSupportSessionEndType {
  description: String,
}


sig SharedLinkChangeExpiryDetails {
  previous_value: lone DropboxTimestamp,
  new_value: lone DropboxTimestamp,
}


sig ListFileRequestsContinueArg {
  cursor: String,
}


sig FileLockContent {
  .tag: String,
}


sig SharingUserError {
  .tag: String,
}


sig PaperDocUpdateError {
  .tag: String,
}


sig InsufficientQuotaAmounts {
  space_shortage: Int,
  space_left: Int,
  space_needed: Int,
}


sig FileRequestsEmailsEnabledDetails {
}


sig GetAccountError {
  .tag: String,
}


sig ReadPath {
  // Generic object with no specific type
}


sig SsoRemoveLogoutUrlType {
  description: String,
}


sig FeatureValue {
  .tag: String,
}


sig LegalHoldsPolicyUpdateArg {
  description: lone LegalHoldPolicyDescription,
  members: lone set TeamMemberId,
  name: lone LegalHoldPolicyName,
  id: LegalHoldId,
}


sig CreateFolderArg {
  path: WritePath,
  autorename: Bool,
}


sig LinkPermission {
  action: LinkAction,
  reason: lone PermissionDeniedReason,
  allow: Bool,
}


sig ResendVerificationEmailResult {
  results: set UserResendResult,
}


sig UploadSessionFinishBatchJobStatus {
  .tag: String,
}


sig LinkAudienceDisallowedReason {
  .tag: String,
}


sig SharedLinkSettingsChangeExpirationType {
  description: String,
}


sig DropboxPasswordsNewDeviceEnrolledType {
  description: String,
}


sig ShowcaseViewDetails {
  event_uuid: String,
}


sig SharedLinkError {
  .tag: String,
}


sig MembersGetInfoError {
  .tag: String,
}


sig ParentFolderAccessInfo {
  permissions: set MemberPermission,
  folder_name: String,
  shared_folder_id: SharedFolderId,
  path: String,
}


sig GetTemplateResult {
  // Generic object with no specific type
}


sig GetFileMetadataIndividualResult {
  .tag: String,
}


sig TokenGetAuthenticatedAdminResult {
  admin_profile: TeamMemberProfile,
}


sig GroupRenameDetails {
  previous_value: String,
  new_value: String,
}


sig PaperFolderChangeSubscriptionDetails {
  event_uuid: String,
  new_subscription_level: String,
  previous_subscription_level: lone String,
}


sig TeamActivityCreateReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig TeamExtensionsPolicy {
  .tag: String,
}


sig SymlinkInfo {
  target: String,
}


sig FullTeam {
  // Generic object with no specific type
}


sig PaperDocSlackShareDetails {
  event_uuid: String,
}


sig TeamFolderChangeStatusDetails {
  new_value: TeamFolderStatus,
  previous_value: lone TeamFolderStatus,
}


sig RewindFolderType {
  description: String,
}


sig MembersGetInfoItemBase {
  .tag: String,
}


sig UnshareFolderArg {
  leave_a_copy: Bool,
  shared_folder_id: SharedFolderId,
}


sig GroupsGetInfoResult {
  items: set GroupsGetInfoItem
}


sig OriginLogInfo {
  access_method: AccessMethodLogInfo,
  geo_location: lone GeoLocationLogInfo,
}


sig DeviceLinkFailDetails {
  ip_address: lone IpAddress,
  device_type: DeviceType,
}


sig InviteeMembershipInfo {
  // Generic object with no specific type
}


sig PropertyGroupUpdate {
  add_or_update_fields: lone set PropertyField,
  remove_fields: lone set String,
  template_id: TemplateId,
}


sig ExternalDriveBackupStatusChangedType {
  description: String,
}


sig GroupExternalId {
  // Primitive type: string
  value: String
}


sig TeamProfileChangeDefaultLanguageDetails {
  previous_value: LanguageCode,
  new_value: LanguageCode,
}


sig UploadSessionFinishBatchArg {
  entries: set UploadSessionFinishArg,
}


sig GetAccountBatchArg {
  account_ids: set AccountId,
}


sig MembersListResult {
  cursor: String,
  members: set TeamMemberInfo,
  has_more: Bool,
}


sig ShowcaseRequestAccessDetails {
  event_uuid: String,
}


sig CreateSharedLinkWithSettingsError {
  .tag: String,
}


sig SharedLinkRemoveExpiryType {
  description: String,
}


sig MemberPolicy {
  .tag: String,
}


sig ListFileMembersError {
  .tag: String,
}


sig NumberPerDay {
  items: set Int
}


sig TeamFolderArchiveArg {
  // Generic object with no specific type
}


sig UpdateFileRequestError {
  .tag: String,
}


sig SfFbInviteChangeRoleDetails {
  original_folder_name: String,
  new_sharing_permission: lone String,
  target_asset_index: Int,
  previous_sharing_permission: lone String,
}


sig UserTagsAddedType {
  description: String,
}


sig LockFileArg {
  path: WritePathOrId,
}


sig ShowcaseAccessGrantedType {
  description: String,
}


sig IntegrationPolicyChangedDetails {
  new_value: IntegrationPolicy,
  previous_value: IntegrationPolicy,
  integration_name: String,
}


sig SharedLinkSettingsChangePasswordDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig GovernancePolicyCreateType {
  description: String,
}


sig EmmRemoveExceptionType {
  description: String,
}


sig GetMembershipReport {
  // Generic object with no specific type
}


sig FileMetadata {
  // Generic object with no specific type
}


sig CreateFolderBatchResult {
  // Generic object with no specific type
}


sig LoginSuccessDetails {
  is_emm_managed: lone Bool,
  login_method: LoginMethod,
}


sig PaperPublishedLinkViewType {
  description: String,
}


sig LegalHoldsGetPolicyError {
  .tag: String,
}


sig Folder {
  id: String,
  name: String,
}


sig SharedLinkDisableType {
  description: String,
}


sig ExternalDriveBackupPolicyChangedType {
  description: String,
}


sig MediaMetadata {
  time_taken: lone DropboxTimestamp,
  dimensions: lone Dimensions,
  location: lone GpsCoordinates,
}


sig ThumbnailV2Error {
  .tag: String,
}


sig AccountCaptureNotificationType {
  .tag: String,
}


sig SharingLinkPolicy {
  .tag: String,
}


sig GetTemporaryUploadLinkResult {
  link: String,
}


sig MemberChangeAdminRoleType {
  description: String,
}


sig PrimaryTeamRequestCanceledDetails {
  secondary_team: String,
  sent_by: String,
}


sig PasswordResetAllType {
  description: String,
}


sig AddPaperDocUserResult {
  .tag: String,
}


sig GroupMembersAddError {
  .tag: String,
}


sig SearchOptions {
  file_categories: lone set FileCategory,
  filename_only: Bool,
  file_extensions: lone set String,
  order_by: lone SearchOrderBy,
  path: lone PathROrId,
  account_id: lone AccountId,
  file_status: FileStatus,
  max_results: Int,
}


sig MembersAddV2Arg {
  // Generic object with no specific type
}


sig FileAddCommentType {
  description: String,
}


sig AccountState {
  .tag: String,
}


sig OfficeAddInPolicy {
  .tag: String,
}


sig GroupUpdateArgs {
  // Generic object with no specific type
}


sig PermanentDeleteChangePolicyDetails {
  previous_value: lone ContentPermanentDeletePolicy,
  new_value: ContentPermanentDeletePolicy,
}


sig GetFileMetadataBatchArg {
  actions: lone set FileAction,
  files: set PathOrId,
}


sig RevokeLinkedAppStatus {
  success: Bool,
  error_type: lone RevokeLinkedAppError,
}


sig SharedLinkViewDetails {
  shared_link_owner: lone UserLogInfo,
}


sig CopyBatchArg {
  // Generic object with no specific type
}


sig FileSaveCopyReferenceType {
  description: String,
}


sig TfaRemoveSecurityKeyDetails {
}


sig FoldersContainingPaperDoc {
  folder_sharing_policy_type: lone FolderSharingPolicyType,
  folders: lone set Folder,
}


sig GroupCreateError {
  .tag: String,
}


sig SharedLinkCreatePolicy {
  .tag: String,
}


sig MemberSelectorError {
  .tag: String,
}


sig EmmCreateUsageReportType {
  description: String,
}


sig SharedContentAddLinkExpiryDetails {
  new_value: lone DropboxTimestamp,
}


sig EmmRefreshAuthTokenDetails {
}


sig VisibilityPolicy {
  resolved_policy: AlphaResolvedVisibility,
  allowed: Bool,
  disallowed_reason: lone VisibilityPolicyDisallowedReason,
  policy: RequestedVisibility,
}


sig GetFileMetadataError {
  .tag: String,
}


sig RelinquishFileMembershipArg {
  file: PathOrId,
}


sig SecondaryEmailDeletedDetails {
  secondary_email: EmailAddress,
}


sig DocSubscriptionLevel {
  .tag: String,
}


sig WriteConflictError {
  .tag: String,
}


sig FolderLogInfo {
  // Generic object with no specific type
}


sig FilePreviewType {
  description: String,
}


sig AdminConsoleAppPolicy {
  .tag: String,
}


sig ExternalUserLogInfo {
  identifier_type: IdentifierType,
  user_identifier: String,
}


sig DataResidencyMigrationRequestUnsuccessfulDetails {
}


sig LogoutDetails {
  login_id: lone String,
}


sig PaperDocOwnershipChangedDetails {
  new_owner_user_id: AccountId,
  event_uuid: String,
  old_owner_user_id: lone AccountId,
}


sig TeamEncryptionKeyScheduleKeyDeletionType {
  description: String,
}


sig ListFilesArg {
  limit: Int,
  actions: lone set FileAction,
}


sig UserCustomQuotaResult {
  quota_gb: lone UserQuota,
  user: UserSelectorArg,
}


sig ExcludedUsersListContinueError {
  .tag: String,
}


sig PaperDocCreateError {
  .tag: String,
}


sig FileRequestsPolicy {
  .tag: String,
}


sig AssetLogInfo {
  .tag: String,
}


sig BackupStatus {
  .tag: String,
}


sig DeviceUnlinkPolicy {
  .tag: String,
}


sig ObjectLabelAddedDetails {
  label_type: LabelType,
}


sig GroupsListArg {
  limit: Int,
}


sig TeamMergeRequestReminderExtraDetails {
  .tag: String,
}


sig GroupsListContinueError {
  .tag: String,
}


sig SsoRemoveCertDetails {
}


sig AddSecondaryEmailsArg {
  new_secondary_emails: set UserSecondaryEmailsArg,
}


sig ListMemberDevicesResult {
  desktop_client_sessions: lone set DesktopClientSession,
  active_web_sessions: lone set ActiveWebSession,
  mobile_client_sessions: lone set MobileClientSession,
}


sig MemberPermanentlyDeleteAccountContentsType {
  description: String,
}


sig PaperFolderLogInfo {
  folder_name: String,
  folder_id: String,
}


sig TeamExtensionsPolicyChangedType {
  description: String,
}


sig GroupDeleteError {
  .tag: String,
}


sig WebSessionsIdleLengthPolicy {
  .tag: String,
}


sig ShowcaseTrashedDetails {
  event_uuid: String,
}


sig GetCopyReferenceResult {
  copy_reference: String,
  expires: DropboxTimestamp,
  metadata: Metadata,
}


sig FolderOverviewItemPinnedDetails {
  folder_overview_location_asset: Int,
  pinned_items_asset_indices: set Int,
}


sig TeamMergeRequestRevokedDetails {
  team: String,
}


sig TeamMergeRequestExpiredShownToPrimaryTeamType {
  description: String,
}


sig PaperContentAddToFolderDetails {
  event_uuid: String,
  target_asset_index: Int,
  parent_asset_index: Int,
}


sig PaperDocTeamInviteType {
  description: String,
}


sig DeleteSecondaryEmailResult {
  .tag: String,
}


sig RevokeLinkedAppBatchResult {
  revoke_linked_app_status: set RevokeLinkedAppStatus,
}


sig MembersAddArg {
  // Generic object with no specific type
}


sig GroupMembersSelector {
  users: UsersSelectorArg,
  group: GroupSelector,
}


sig InviteAcceptanceEmailPolicyChangedDetails {
  previous_value: InviteAcceptanceEmailPolicy,
  new_value: InviteAcceptanceEmailPolicy,
}


sig WritePathOrId {
  // Primitive type: string
  value: String
}


sig LockFileResultEntry {
  .tag: String,
}


sig GovernancePolicyAddFoldersType {
  description: String,
}


sig UpdateFolderPolicyError {
  .tag: String,
}


sig ListFileMembersArg {
  file: PathOrId,
  actions: lone set MemberAction,
  include_inherited: Bool,
  limit: Int,
}


sig SharingChangeFolderJoinPolicyDetails {
  new_value: SharingFolderJoinPolicy,
  previous_value: lone SharingFolderJoinPolicy,
}


sig SecondaryEmailDeletedType {
  description: String,
}


sig GetThumbnailBatchResultData {
  thumbnail: String,
  metadata: FileMetadata,
}


sig TeamSharingWhitelistSubjectsChangedDetails {
  added_whitelist_subjects: set String,
  removed_whitelist_subjects: set String,
}


sig ExternalSharingCreateReportType {
  description: String,
}


sig GetThumbnailBatchResult {
  entries: set GetThumbnailBatchResultEntry,
}


sig NamePart {
  // Primitive type: string
  value: String
}


sig AppPermissionsChangedType {
  description: String,
}


sig DownloadError {
  .tag: String,
}


sig MembersGetInfoResult {
  items: set MembersGetInfoItem
}


sig ExportMembersReportFailType {
  description: String,
}


sig MembersSuspendError {
  .tag: String,
}


sig IntegrationPolicyChangedType {
  description: String,
}


sig UnlockFileArg {
  path: WritePathOrId,
}


sig LinkSettings {
  access_level: lone AccessLevel,
  audience: lone LinkAudience,
  expiry: lone LinkExpiry,
  password: lone LinkPassword,
}


sig StorageBucket {
  bucket: String,
  users: Int,
}


sig DeleteBatchResultEntry {
  .tag: String,
}


sig FeaturesGetValuesBatchResult {
  values: set FeatureValue,
}


sig ExternalSharingReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig MemberAddNameDetails {
  new_value: UserNameLogInfo,
}


sig SfTeamJoinType {
  description: String,
}


sig WebSessionsChangeFixedLengthPolicyType {
  description: String,
}


sig LegalHoldsReleaseAHoldDetails {
  name: String,
  legal_hold_id: String,
}


sig FileLikeCommentDetails {
  comment_text: lone String,
}


sig DropboxPasswordsPolicyChangedDetails {
  previous_value: DropboxPasswordsPolicy,
  new_value: DropboxPasswordsPolicy,
}


sig EndedEnterpriseAdminSessionDeprecatedType {
  description: String,
}


sig RemoveFolderMemberArg {
  shared_folder_id: SharedFolderId,
  member: MemberSelector,
  leave_a_copy: Bool,
}


sig CameraUploadsPolicyState {
  .tag: String,
}


sig AccountCaptureChangePolicyType {
  description: String,
}


sig TeamEncryptionKeyRotateKeyDetails {
}


sig DesktopPlatform {
  .tag: String,
}


sig AddFolderMemberError {
  .tag: String,
}


sig GovernancePolicyDeleteDetails {
  name: String,
  policy_type: lone PolicyType,
  governance_policy_id: String,
}


sig AllowDownloadDisabledType {
  description: String,
}


sig PaperUpdateError {
  .tag: String,
}


sig AddSecondaryEmailsError {
  .tag: String,
}


sig SetAccessInheritanceError {
  .tag: String,
}


sig MoveIntoFamilyError {
  .tag: String,
}


sig ListFolderArg {
  recursive: Bool,
  include_mounted_folders: Bool,
  include_media_info: Bool,
  shared_link: lone SharedLink,
  include_has_explicit_shared_members: Bool,
  include_non_downloadable_files: Bool,
  include_deleted: Bool,
  limit: lone Int,
  include_property_groups: lone TemplateFilterBase,
  path: PathROrId,
}


sig SearchArg {
  mode: SearchMode,
  query: String,
  start: Int,
  max_results: Int,
  path: PathROrId,
}


sig ShmodelEnableDownloadsDetails {
  shared_link_owner: lone UserLogInfo,
}


sig PaperUpdateResult {
  paper_revision: Int,
}


sig ObjectLabelUpdatedValueDetails {
  label_type: LabelType,
}


sig OpenNoteSharedDetails {
}


sig SharedFolderJoinPolicy {
  .tag: String,
}


sig TeamEncryptionKeyScheduleKeyDeletionDetails {
}


sig AppUnlinkUserType {
  description: String,
}


sig LegalHoldsExportRemovedType {
  description: String,
}


sig TeamMergeRequestSentShownToSecondaryTeamDetails {
  sent_to: String,
}


sig NamespaceId {
  // Primitive type: string
  value: String
}


sig MemberAddNameType {
  description: String,
}


sig ShowcaseUntrashedDetails {
  event_uuid: String,
}


sig NoteAclTeamLinkType {
  description: String,
}


sig TeamLinkedAppLogInfo {
  // Generic object with no specific type
}


sig NetworkControlChangePolicyDetails {
  previous_value: lone NetworkControlPolicy,
  new_value: NetworkControlPolicy,
}


sig FileProviderMigrationPolicyChangedType {
  description: String,
}


sig SharedContentAddLinkPasswordType {
  description: String,
}


sig SharedContentDownloadType {
  description: String,
}


sig GetSharedLinkMetadataArg {
  link_password: lone String,
  url: String,
  path: lone Path,
}


sig ClassificationType {
  .tag: String,
}


sig ViewerInfoPolicyChangedType {
  description: String,
}


sig FileRequest {
  id: FileRequestId,
  title: String,
  file_count: Int,
  created: DropboxTimestamp,
  is_open: Bool,
  deadline: lone FileRequestDeadline,
  description: lone String,
  url: String,
  destination: lone Path,
}


sig UserInfoError {
  .tag: String,
}


sig ExcludedUsersUpdateError {
  .tag: String,
}


sig TfaChangePolicyType {
  description: String,
}


sig DeleteSecondaryEmailsResult {
  results: set UserDeleteResult,
}


sig MemberSuggestionsPolicy {
  .tag: String,
}


sig ListUsersOnPaperDocArgs {
  // Generic object with no specific type
}


sig UploadSessionCursor {
  offset: Int,
  session_id: String,
}


sig RelocationBatchV2Launch {
  .tag: String,
}


sig FileAddFromAutomationDetails {
}


sig TeamFolderUpdateSyncSettingsError {
  .tag: String,
}


sig FileCopyDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig PaperChangeMemberLinkPolicyDetails {
  new_value: PaperMemberPolicy,
}


sig ListUsersOnFolderArgs {
  // Generic object with no specific type
}


sig SharedContentRemoveLinkExpiryType {
  description: String,
}


sig ShowcaseDeleteCommentType {
  description: String,
}


sig FileCommentNotificationPolicy {
  .tag: String,
}


sig FileTransfersTransferViewDetails {
  file_transfer_id: String,
}


sig AdminAlertingAlertStateChangedDetails {
  alert_name: String,
  alert_instance_id: String,
  alert_severity: AdminAlertSeverityEnum,
  alert_category: AdminAlertCategoryEnum,
  previous_value: AdminAlertGeneralStateEnum,
  new_value: AdminAlertGeneralStateEnum,
}


sig UserResendResult {
  .tag: String,
}


sig FilePermission {
  reason: lone PermissionDeniedReason,
  action: FileAction,
  allow: Bool,
}


sig CustomQuotaResult {
  .tag: String,
}


sig OpenNoteSharedType {
  description: String,
}


sig SetProfilePhotoArg {
  photo: PhotoSourceArg,
}


sig ModifyTemplateError {
  .tag: String,
}


sig LegalHoldsError {
  .tag: String,
}


sig ShowcaseAccessGrantedDetails {
  event_uuid: String,
}


sig UnmountFolderError {
  .tag: String,
}


sig CommitInfo {
  path: WritePathOrId,
  mode: WriteMode,
  autorename: Bool,
  mute: Bool,
  client_modified: lone DropboxTimestamp,
  property_groups: lone set PropertyGroup,
  strict_conflict: Bool,
}


sig SharedContentRemoveLinkPasswordType {
  description: String,
}


sig ListFileMembersContinueArg {
  cursor: String,
}


sig TeamProfileChangeBackgroundType {
  description: String,
}


sig SaveUrlError {
  .tag: String,
}


sig AppLinkUserDetails {
  app_info: AppLogInfo,
}


sig ModifySharedLinkSettingsArgs {
  settings: SharedLinkSettings,
  url: String,
  remove_expiration: Bool,
}


sig DurationLogInfo {
  amount: Int,
  unit: TimeUnit,
}


sig ExcludedUsersListArg {
  limit: Int,
}


sig SharedFolderUnmountDetails {
}


sig TeamMergeRequestCanceledShownToPrimaryTeamDetails {
  sent_by: String,
  secondary_team: String,
}


sig FileRequestReceiveFileType {
  description: String,
}


sig WebDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig CameraUploadsPolicyChangedType {
  description: String,
}


sig NoPasswordLinkViewCreateReportType {
  description: String,
}


sig PaperMemberPolicy {
  .tag: String,
}


sig ListFilesContinueError {
  .tag: String,
}


sig MemberRemoveExternalIdDetails {
  previous_value: MemberExternalId,
}


sig ListFolderContinueError {
  .tag: String,
}


sig MembersDeleteProfilePhotoArg {
  user: UserSelectorArg,
}


sig ListMembersDevicesResult {
  devices: set MemberDevices,
  has_more: Bool,
  cursor: lone String,
}


sig TeamFolderStatus {
  .tag: String,
}


sig ApiApp {
  linked: lone DropboxTimestamp,
  is_app_folder: Bool,
  app_name: String,
  publisher: lone String,
  app_id: String,
  publisher_url: lone String,
}


sig TeamMemberStatus {
  .tag: String,
}


sig DeviceApprovalsChangeMobilePolicyType {
  description: String,
}


sig GroupCreateType {
  description: String,
}


sig TransferFolderError {
  .tag: String,
}


sig CountFileRequestsResult {
  file_request_count: Int,
}


sig ReplayProjectTeamDeleteType {
  description: String,
}


sig UserAddResult {
  .tag: String,
}


sig GovernancePolicyZipPartDownloadedDetails {
  governance_policy_id: String,
  policy_type: lone PolicyType,
  name: String,
  part: lone String,
  export_name: String,
}


sig FileMemberActionIndividualResult {
  .tag: String,
}


sig TeamActivityCreateReportType {
  description: String,
}


sig GetAccountBatchResult {
  items: set BasicAccount
}


sig AccountLockOrUnlockedDetails {
  new_value: AccountState,
  previous_value: AccountState,
}


sig PaperChangeMemberLinkPolicyType {
  description: String,
}


sig ListFoldersContinueError {
  .tag: String,
}


sig PaperFolderDeletedType {
  description: String,
}


sig AppUnlinkUserDetails {
  app_info: AppLogInfo,
}


sig PaperDocPermissionLevel {
  .tag: String,
}


sig TeamMemberInfoV2Result {
  member_info: TeamMemberInfoV2,
}


sig DownloadZipArg {
  path: ReadPath,
}


sig NoExpirationLinkGenCreateReportDetails {
  end_date: DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig PropertiesSearchArg {
  template_filter: TemplateFilter,
  queries: set PropertiesSearchQuery,
}


sig WebSessionsFixedLengthPolicy {
  .tag: String,
}


sig SharedFolderMembers {
  groups: set GroupMembershipInfo,
  users: set UserMembershipInfo,
  cursor: lone String,
  invitees: set InviteeMembershipInfo,
}


sig WriteError {
  .tag: String,
}


sig FileAddCommentDetails {
  comment_text: lone String,
}


sig SharedLinkChangeExpiryType {
  description: String,
}


sig MemberSpaceLimitsAddExceptionDetails {
}


sig PaperChangeDeploymentPolicyType {
  description: String,
}


sig AccountLockOrUnlockedType {
  description: String,
}


sig NoPasswordLinkGenCreateReportType {
  description: String,
}


sig ShowcaseAddMemberDetails {
  event_uuid: String,
}


sig TeamFolderCreateDetails {
}


sig TeamSelectiveSyncPolicy {
  .tag: String,
}


sig TemplateId {
  // Primitive type: string
  value: String
}


sig AppBlockedByPermissionsType {
  description: String,
}


sig CaptureTranscriptPolicy {
  .tag: String,
}


sig MemberAddResult {
  .tag: String,
}


sig PropertiesSearchContinueError {
  .tag: String,
}


sig PropertiesSearchMode {
  .tag: String,
}


sig TokenFromOAuth1Error {
  .tag: String,
}


sig SetAccessInheritanceArg {
  access_inheritance: AccessInheritance,
  shared_folder_id: SharedFolderId,
}


sig UploadArg {
  // Generic object with no specific type
}


sig ListFileMembersBatchResult {
  result: ListFileMembersIndividualResult,
  file: PathOrId,
}


sig TeamFolderPermanentlyDeleteType {
  description: String,
}


sig EmailIngestPolicyChangedType {
  description: String,
}


sig TfaChangeBackupPhoneDetails {
}


sig TeamMemberLogInfo {
  // Generic object with no specific type
}


sig ListTeamDevicesArg {
  include_mobile_clients: Bool,
  include_web_sessions: Bool,
  cursor: lone String,
  include_desktop_clients: Bool,
}


sig FullAccount {
  // Generic object with no specific type
}


sig TeamSharingPolicies {
  shared_folder_member_policy: SharedFolderMemberPolicy,
  shared_folder_join_policy: SharedFolderJoinPolicy,
  group_creation_policy: GroupCreation,
  shared_folder_link_restriction_policy: SharedFolderBlanketLinkRestrictionPolicy,
  shared_link_create_policy: SharedLinkCreatePolicy,
}


sig RelocationError {
  .tag: String,
}


sig SharedFolderBlanketLinkRestrictionPolicy {
  .tag: String,
}


sig ClassificationCreateReportFailType {
  description: String,
}


sig SmarterSmartSyncPolicyChangedType {
  description: String,
}


sig LegalHoldsActivateAHoldType {
  description: String,
}


sig TeamEncryptionKeyCreateKeyDetails {
}


sig PaperFolderCreateError {
  .tag: String,
}


sig DisabledDomainInvitesType {
  description: String,
}


sig RemovePropertiesArg {
  path: PathOrId,
  property_template_ids: set TemplateId,
}


sig FileRestoreDetails {
}


sig GroupSelector {
  .tag: String,
}


sig FileId {
  // Primitive type: string
  value: String
}


sig RestoreArg {
  path: WritePath,
  rev: Rev,
}


sig RelocationBatchResultEntry {
  .tag: String,
}


sig FileRequestDeleteDetails {
  file_request_id: lone FileRequestId,
  previous_details: lone FileRequestDetails,
}


sig SetCustomQuotaError {
  .tag: String,
}


sig PaperDocMentionType {
  description: String,
}


sig SharingPublicPolicyType {
  .tag: String,
}


sig SecondaryTeamRequestExpiredDetails {
  sent_to: String,
}


sig MemberDeleteProfilePhotoDetails {
}


sig HighlightSpan {
  highlight_str: String,
  is_highlighted: Bool,
}


sig LegalHoldsPolicyCreateArg {
  description: lone LegalHoldPolicyDescription,
  end_date: lone DropboxTimestamp,
  start_date: lone DropboxTimestamp,
  name: LegalHoldPolicyName,
  members: set TeamMemberId,
}


sig PasswordChangeType {
  description: String,
}


sig MembersGetInfoV2Result {
  members_info: set MembersGetInfoItemV2,
}


sig IdentifierType {
  .tag: String,
}


sig RelinquishFileMembershipError {
  .tag: String,
}


sig MembersAddJobStatus {
  .tag: String,
}


sig SharedContentAddInviteesDetails {
  invitees: set EmailAddress,
  shared_content_access_level: AccessLevel,
}


sig GovernancePolicyReportCreatedType {
  description: String,
}


sig InviteMethod {
  .tag: String,
}


sig GroupDescriptionUpdatedDetails {
}


sig BaseTeamFolderError {
  .tag: String,
}


sig DomainVerificationAddDomainFailDetails {
  verification_method: lone String,
  domain_name: String,
}


sig SfTeamGrantAccessType {
  description: String,
}


sig ResendVerificationEmailArg {
  emails_to_resend: set UserSecondaryEmailsArg,
}


sig GroupAddExternalIdType {
  description: String,
}


sig PlacementRestriction {
  .tag: String,
}


sig EmailAddress {
  // Primitive type: string
  value: String
}


sig ExternalDriveBackupEligibilityStatusCheckedDetails {
  status: ExternalDriveBackupEligibilityStatus,
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
  number_of_external_drive_backup: Int,
}


sig TeamMergeRequestExpiredShownToSecondaryTeamType {
  description: String,
}


sig DeviceChangeIpDesktopDetails {
  device_session_info: DeviceSessionLogInfo,
}


sig UserTagsAddedDetails {
  values: set String,
}


sig InviteeInfo {
  .tag: String,
}


sig SharedLinkSettingsAddExpirationType {
  description: String,
}


sig LegalHoldsPolicyCreateError {
  .tag: String,
}


sig TeamRootInfo {
  // Generic object with no specific type
}


sig ListRevisionsArg {
  path: PathOrId,
  limit: Int,
  mode: ListRevisionsMode,
}


sig LinkAudience {
  .tag: String,
}


sig DomainInvitesDeclineRequestToJoinTeamDetails {
}


sig TeamFolderRenameDetails {
  previous_folder_name: String,
  new_folder_name: String,
}


sig SharedFolderChangeMembersManagementPolicyType {
  description: String,
}


sig SharedFolderTransferOwnershipType {
  description: String,
}


sig SfFbInviteChangeRoleType {
  description: String,
}


sig PaperDesktopPolicyChangedDetails {
  new_value: PaperDesktopPolicy,
  previous_value: PaperDesktopPolicy,
}


sig ShowcaseTrashedDeprecatedType {
  description: String,
}


sig GroupRemoveExternalIdType {
  description: String,
}


sig ListSharedLinksError {
  .tag: String,
}


sig EnterpriseSettingsLockingDetails {
  new_settings_page_locking_state: String,
  previous_settings_page_locking_state: String,
  team_name: String,
  settings_page_name: String,
}


sig DeleteBatchResultData {
  metadata: Metadata,
}


sig PaperPublishedLinkDisabledType {
  description: String,
}


sig TfaAddBackupPhoneType {
  description: String,
}


sig ExternalDriveBackupEligibilityStatus {
  .tag: String,
}


sig UserFeaturesGetValuesBatchError {
  .tag: String,
}


sig UploadSessionFinishArg {
  cursor: UploadSessionCursor,
  commit: CommitInfo,
  content_hash: lone Sha256HexHash,
}


sig SearchMatchFieldOptions {
  include_highlights: Bool,
}


sig ActiveWebSession {
  // Generic object with no specific type
}


sig AddPaperDocUser {
  // Generic object with no specific type
}


sig TeamFolderListContinueArg {
  cursor: String,
}


sig TeamBrandingPolicy {
  .tag: String,
}


sig GroupChangeMemberRoleDetails {
  is_group_owner: Bool,
}


sig Visibility {
  .tag: String,
}


sig SharedLinkAccessFailureReason {
  .tag: String,
}


sig MembersSetPermissions2Result {
  team_member_id: TeamMemberId,
  roles: lone set TeamMemberRole,
}


sig ShowcaseEditedType {
  description: String,
}


sig SharedLinkSettingsRemovePasswordDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
}


sig SharingAllowlistAddResponse {
}


sig UserInfoResult {
  email_verified: lone Bool,
  sub: String,
  email: lone String,
  given_name: lone String,
  family_name: lone String,
  iss: String,
}


sig SharedLinkAddExpiryDetails {
  new_value: DropboxTimestamp,
}


sig FileDeleteCommentType {
  description: String,
}


sig OrganizeFolderWithTidyDetails {
}


sig FileProviderMigrationPolicyChangedDetails {
  previous_value: FileProviderMigrationPolicyState,
  new_value: FileProviderMigrationPolicyState,
}


sig ActionDetails {
  .tag: String,
}


sig UndoNamingConventionType {
  description: String,
}


sig FileRequestCloseType {
  description: String,
}


sig CreateFolderEntryError {
  .tag: String,
}


sig DeviceApprovalsChangeUnlinkActionDetails {
  new_value: lone DeviceUnlinkPolicy,
  previous_value: lone DeviceUnlinkPolicy,
}


sig PaperExternalViewDefaultTeamDetails {
  event_uuid: String,
}


sig GetFileRequestError {
  .tag: String,
}


sig UploadApiRateLimitValue {
  .tag: String,
}


sig SsoRemoveLogoutUrlDetails {
  previous_value: String,
}


sig BackupInvitationOpenedType {
  description: String,
}


sig DeviceDeleteOnUnlinkFailType {
  description: String,
}


sig TeamFolderListArg {
  limit: Int,
}


sig GroupRenameType {
  description: String,
}


sig MembersUnsuspendError {
  .tag: String,
}


sig AccessInheritance {
  .tag: String,
}


sig LegalHoldStatus {
  .tag: String,
}


sig PollResultBase {
  .tag: String,
}


sig NoPasswordLinkGenCreateReportDetails {
  end_date: DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig MemberDeleteManualContactsDetails {
}


sig SetProfilePhotoError {
  .tag: String,
}


sig FileTransfersTransferDownloadType {
  description: String,
}


sig AdminAlertingAlertStatePolicy {
  .tag: String,
}


sig UndoNamingConventionDetails {
}


sig SmartSyncCreateAdminPrivilegeReportType {
  description: String,
}


sig ListUsersOnPaperDocContinueArgs {
  // Generic object with no specific type
}


sig TeamFolderDowngradeDetails {
  target_asset_index: Int,
}


sig DeviceSessionArg {
  session_id: String,
  team_member_id: String,
}


sig ComputerBackupPolicyChangedType {
  description: String,
}


sig NoPasswordLinkGenReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig PaperFolderCreateResult {
  folder_id: String,
}


sig LogoutType {
  description: String,
}


sig ListFoldersResult {
  cursor: lone String,
  entries: set SharedFolderMetadata,
}


sig ConnectedTeamName {
  team: String,
}


sig MemberChangeNameDetails {
  new_value: UserNameLogInfo,
  previous_value: lone UserNameLogInfo,
}


sig Path {
  // Primitive type: string
  value: String
}


sig ComputerBackupPolicyState {
  .tag: String,
}


sig RevokeLinkedApiAppBatchArg {
  revoke_linked_app: set RevokeLinkedApiAppArg,
}


sig UploadSessionFinishError {
  .tag: String,
}


sig UserFeaturesGetValuesBatchArg {
  features: set UserFeature,
}


sig GoogleSsoChangePolicyDetails {
  new_value: GoogleSsoPolicy,
  previous_value: lone GoogleSsoPolicy,
}


sig TeamMergeRequestReminderShownToSecondaryTeamDetails {
  sent_to: String,
}


sig MembersDeleteProfilePhotoError {
  .tag: String,
}


sig HasTeamSharedDropboxValue {
  .tag: String,
}


sig SsoChangeLogoutUrlDetails {
  new_value: lone String,
  previous_value: lone String,
}


sig SharingAllowlistRemoveError {
  .tag: String,
}


sig RevokeLinkedAppError {
  .tag: String,
}


sig ListFoldersContinueArg {
  cursor: String,
}


sig PaperDocChangeSubscriptionType {
  description: String,
}


sig MemberSelector {
  .tag: String,
}


sig VisibilityPolicyDisallowedReason {
  .tag: String,
}


sig DataPlacementRestrictionSatisfyPolicyDetails {
  placement_restriction: PlacementRestriction,
}


sig LegalHoldsGetPolicyArg {
  id: LegalHoldId,
}


sig TfaResetDetails {
}


sig DeleteFileRequestsResult {
  file_requests: set FileRequest,
}


sig MemberRemoveActionType {
  .tag: String,
}


sig SharedContentRemoveLinkPasswordDetails {
}


sig FileEditDetails {
}


sig UserOnPaperDocFilter {
  .tag: String,
}


sig OpenIdError {
  .tag: String,
}


sig FileChangeCommentSubscriptionDetails {
  previous_value: lone FileCommentNotificationPolicy,
  new_value: FileCommentNotificationPolicy,
}


sig MembersDeactivateError {
  .tag: String,
}


sig DeleteResult {
  // Generic object with no specific type
}


sig FilePermanentlyDeleteDetails {
}


sig FileLogInfo {
  // Generic object with no specific type
}


sig SharingChangeFolderJoinPolicyType {
  description: String,
}


sig TrustedNonTeamMemberLogInfo {
  // Generic object with no specific type
}


sig DeviceLinkFailType {
  description: String,
}


sig CreateFileRequestError {
  .tag: String,
}


sig RansomwareRestoreProcessStartedType {
  description: String,
}


sig PaperAccessType {
  .tag: String,
}


sig SfTeamInviteChangeRoleDetails {
  target_asset_index: Int,
  new_sharing_permission: lone String,
  previous_sharing_permission: lone String,
  original_folder_name: String,
}


sig ClassificationPolicyEnumWrapper {
  .tag: String,
}


sig RemovePaperDocUser {
  // Generic object with no specific type
}


sig ShowcaseFileDownloadType {
  description: String,
}


sig DeviceDeleteOnUnlinkSuccessDetails {
  session_info: lone SessionLogInfo,
  display_name: lone String,
}


sig GroupSummary {
  group_external_id: lone GroupExternalId,
  member_count: lone Int,
  group_management_type: GroupManagementType,
  group_name: String,
  group_id: GroupId,
}


sig ContentSyncSetting {
  id: FileId,
  sync_setting: SyncSetting,
}


sig MembersSetPermissionsError {
  .tag: String,
}


sig HasTeamFileEventsValue {
  .tag: String,
}


sig GroupMembersAddArg {
  // Generic object with no specific type
}


sig EmmCreateExceptionsReportType {
  description: String,
}


sig SsoRemoveLoginUrlType {
  description: String,
}


sig TeamLogInfo {
  display_name: String,
}


sig SearchMode {
  .tag: String,
}


sig MembersListContinueArg {
  cursor: String,
}


sig CollectionShareDetails {
  album_name: String,
}


sig IntegrationConnectedDetails {
  integration_name: String,
}


sig CreateFolderType {
  description: String,
}


sig ListMembersAppsResult {
  apps: set MemberLinkedApps,
  has_more: Bool,
  cursor: lone String,
}


sig MemberChangeStatusDetails {
  action: lone ActionDetails,
  previous_value: lone MemberStatus,
  new_team: lone String,
  previous_team: lone String,
  new_value: MemberStatus,
}


sig TeamProfileAddLogoDetails {
}


sig LegalHoldsExportCancelledType {
  description: String,
}


sig RelocateAssetReferencesLogInfo {
  src_asset_index: Int,
  dest_asset_index: Int,
}


sig FileMemberActionError {
  .tag: String,
}


sig ComputerBackupPolicy {
  .tag: String,
}


sig MemberRemoveExternalIdType {
  description: String,
}


sig MembersListContinueError {
  .tag: String,
}


sig TfaRemoveBackupPhoneType {
  description: String,
}


sig RansomwareAlertCreateReportFailedType {
  description: String,
}


sig ExternalSharingCreateReportDetails {
}


sig DateRangeError {
  .tag: String,
}


sig GovernancePolicyEditDetailsType {
  description: String,
}


sig PaperDocSlackShareType {
  description: String,
}


sig ListFoldersArgs {
  limit: Int,
  actions: lone set FolderAction,
}


sig DomainVerificationAddDomainFailType {
  description: String,
}


sig SignInAsSessionStartDetails {
}


sig BinderRemoveSectionType {
  description: String,
}


sig ListFolderLongpollArg {
  cursor: ListFolderCursor,
  timeout: Int,
}


sig TeamProfileRemoveBackgroundType {
  description: String,
}


sig SfTeamJoinDetails {
  original_folder_name: String,
  target_asset_index: Int,
}


sig LookupError {
  .tag: String,
}


sig FileRequestCloseDetails {
  previous_details: lone FileRequestDetails,
  file_request_id: lone FileRequestId,
}


sig RewindPolicyChangedType {
  description: String,
}


sig RequestId {
  // Primitive type: string
  value: String
}


sig SharedContentAddLinkExpiryType {
  description: String,
}


sig GovernancePolicyEditDurationType {
  description: String,
}


sig FileTransfersTransferDownloadDetails {
  file_transfer_id: String,
}


sig EndedEnterpriseAdminSessionType {
  description: String,
}


sig GovernancePolicyExportCreatedDetails {
  export_name: String,
  policy_type: lone PolicyType,
  name: String,
  governance_policy_id: String,
}


sig BackupAdminInvitationSentType {
  description: String,
}


sig SharedContentAddMemberType {
  description: String,
}


sig MembersSetPermissions2Error {
  .tag: String,
}


sig LegalHoldsReportAHoldDetails {
  legal_hold_id: String,
  name: String,
}


sig GetStorageReport {
  // Generic object with no specific type
}


sig AllowDownloadEnabledDetails {
}


sig AccountCaptureChangePolicyDetails {
  new_value: AccountCapturePolicy,
  previous_value: lone AccountCapturePolicy,
}


sig PasswordStrengthPolicy {
  .tag: String,
}


sig TeamMembershipType {
  .tag: String,
}


sig GroupChangeManagementTypeDetails {
  previous_value: lone GroupManagementType,
  new_value: GroupManagementType,
}


sig LegalHoldsListHeldRevisionsArg {
  id: LegalHoldId,
}


sig PaperDocEditCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig PropertiesSearchMatch {
  path: String,
  property_groups: set PropertyGroup,
  id: Id,
  is_deleted: Bool,
}


sig ShowcasePermanentlyDeletedDetails {
  event_uuid: String,
}


sig WebSessionsChangeIdleLengthPolicyDetails {
  previous_value: lone WebSessionsIdleLengthPolicy,
  new_value: lone WebSessionsIdleLengthPolicy,
}


sig DropboxPasswordsPolicyChangedType {
  description: String,
}


sig RemoveTagError {
  .tag: String,
}


sig GovernancePolicyRemoveFoldersDetails {
  governance_policy_id: String,
  folders: lone set String,
  name: String,
  policy_type: lone PolicyType,
  reason: lone String,
}


sig SharingChangeLinkAllowChangeExpirationPolicyDetails {
  new_value: EnforceLinkPasswordPolicy,
  previous_value: lone EnforceLinkPasswordPolicy,
}


sig FileRequestsEmailsRestrictedToTeamOnlyType {
  description: String,
}


sig CustomQuotaUsersArg {
  users: set UserSelectorArg,
}


sig RequestedVisibility {
  .tag: String,
}


sig FileRenameDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig RemoveFileMemberArg {
  member: MemberSelector,
  file: PathOrId,
}


sig PaperFolderCreateArg {
  is_team_folder: lone Bool,
  name: String,
  parent_folder_id: lone String,
}


sig FeaturesGetValuesBatchArg {
  features: set Feature,
}


sig DeviceApprovalsRemoveExceptionDetails {
}


sig StartedEnterpriseAdminSessionType {
  description: String,
}


sig GoogleSsoPolicy {
  .tag: String,
}


sig DomainInvitesDeclineRequestToJoinTeamType {
  description: String,
}


sig PendingSecondaryEmailAddedType {
  description: String,
}


sig TeamFolderRenameType {
  description: String,
}


sig SharedLinkVisibility {
  .tag: String,
}


sig ShowcaseEditCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig ExternalDriveBackupStatus {
  .tag: String,
}


sig SharedFolderMountDetails {
}


sig DeleteSecondaryEmailsArg {
  emails_to_delete: set UserSecondaryEmailsArg,
}


sig UploadSessionType {
  .tag: String,
}


sig SharedLinkCopyDetails {
  shared_link_owner: lone UserLogInfo,
}


sig LockFileBatchArg {
  entries: set LockFileArg,
}


sig ShowcaseChangeEnabledPolicyDetails {
  new_value: ShowcaseEnabledPolicy,
  previous_value: ShowcaseEnabledPolicy,
}


sig DirectoryRestrictionsAddMembersType {
  description: String,
}


sig GroupsMembersListArg {
  limit: Int,
  group: GroupSelector,
}


sig MemberProfile {
  account_id: lone AccountId,
  team_member_id: TeamMemberId,
  invited_on: lone DropboxTimestamp,
  joined_on: lone DropboxTimestamp,
  secondary_emails: lone set SecondaryEmail,
  is_directory_restricted: lone Bool,
  profile_photo_url: lone String,
  status: TeamMemberStatus,
  suspended_on: lone DropboxTimestamp,
  name: Name,
  external_id: lone String,
  email: String,
  persistent_id: lone String,
  email_verified: Bool,
  membership_type: TeamMembershipType,
}


sig FileGetCopyReferenceDetails {
}


sig ExportArg {
  path: ReadPath,
  export_format: lone String,
}


sig CaptureTranscriptPolicyChangedDetails {
  new_value: CaptureTranscriptPolicy,
  previous_value: CaptureTranscriptPolicy,
}


sig SharedContentChangeLinkPasswordDetails {
}


sig SecondaryEmail {
  // Generic object with no specific type
}


sig MembershipInfo {
  initials: lone String,
  permissions: lone set MemberPermission,
  access_type: AccessLevel,
  is_inherited: Bool,
}


sig SharedContentRemoveMemberType {
  description: String,
}


sig TeamFolderListResult {
  has_more: Bool,
  team_folders: set TeamFolderMetadata,
  cursor: String,
}


sig MemberSpaceLimitsRemoveExceptionDetails {
}


sig GetTemporaryLinkResult {
  metadata: FileMetadata,
  link: String,
}


sig SharedLinkPolicy {
  .tag: String,
}


sig GroupAddMemberType {
  description: String,
}


sig ExternalDriveBackupEligibilityStatusCheckedType {
  description: String,
}


sig PaperDownloadFormat {
  .tag: String,
}


sig ListUsersCursorError {
  .tag: String,
}


sig TeamFolderCreateArg {
  name: String,
  sync_setting: lone SyncSettingArg,
}


sig TeamProfileChangeLogoType {
  description: String,
}


sig LegalHoldsRemoveMembersType {
  description: String,
}


sig SharedContentRemoveInviteesDetails {
  invitees: set EmailAddress,
}


sig LockStatus {
  .tag: String,
}


sig LegalHoldsListPoliciesArg {
  include_released: Bool,
}


sig EmmCreateUsageReportDetails {
}


sig AccountCaptureAvailability {
  .tag: String,
}


sig LegalHoldsGetPolicyResult {
  // Generic object with no specific type
}


sig RestoreError {
  .tag: String,
}


sig FolderSharingPolicyType {
  .tag: String,
}


sig FileTransfersTransferSendDetails {
  file_transfer_id: String,
}


sig ListRevisionsError {
  .tag: String,
}


sig InviteeInfoWithPermissionLevel {
  invitee: InviteeInfo,
  permission_level: PaperDocPermissionLevel,
}


sig DeviceApprovalsAddExceptionDetails {
}


sig NonTrustedTeamDetails {
  team: String,
}


sig DisplayName {
  // Primitive type: string
  value: String
}


sig ListUsersOnFolderContinueArgs {
  // Generic object with no specific type
}


sig GroupsMembersListContinueError {
  .tag: String,
}


sig SharedLinkShareDetails {
  shared_link_owner: lone UserLogInfo,
  external_users: lone set ExternalUserLogInfo,
}


sig SendForSignaturePolicy {
  .tag: String,
}


sig FileCommentsChangePolicyType {
  description: String,
}


sig SfFbUninviteDetails {
  original_folder_name: String,
  target_asset_index: Int,
}


sig SharedContentChangeInviteeRoleDetails {
  previous_access_level: lone AccessLevel,
  new_access_level: AccessLevel,
  invitee: EmailAddress,
}


sig SharedContentChangeLinkAudienceDetails {
  previous_value: lone LinkAudience,
  new_value: LinkAudience,
}


sig SmartSyncOptOutDetails {
  new_value: SmartSyncOptOutPolicy,
  previous_value: SmartSyncOptOutPolicy,
}


sig UpdateFileMemberArgs {
  access_level: AccessLevel,
  file: PathOrId,
  member: MemberSelector,
}


sig ExternalDriveBackupPolicyState {
  .tag: String,
}


sig DeleteBatchLaunch {
  .tag: String,
}


sig ClassificationChangePolicyDetails {
  classification_type: ClassificationType,
  new_value: ClassificationPolicyEnumWrapper,
  previous_value: ClassificationPolicyEnumWrapper,
}


sig PaperDocAddCommentType {
  description: String,
}


sig WatermarkingPolicy {
  .tag: String,
}


sig LegalHoldPolicyDescription {
  // Primitive type: string
  value: String
}


sig DateRange {
  start_date: lone Date,
  end_date: lone Date,
}


sig FileAction {
  .tag: String,
}


sig TeamEncryptionKeyDisableKeyType {
  description: String,
}


sig PollArg {
  async_job_id: AsyncJobId,
}


sig GroupUserManagementChangePolicyType {
  description: String,
}


sig JobError {
  .tag: String,
}


sig SharingAllowlistAddError {
  .tag: String,
}


sig FedExtraDetails {
  .tag: String,
}


sig DeviceApprovalsRemoveExceptionType {
  description: String,
}


sig FileCategory {
  .tag: String,
}


sig IntegrationConnectedType {
  description: String,
}


sig ActorLogInfo {
  .tag: String,
}


sig ChangedEnterpriseAdminRoleDetails {
  team_name: String,
  previous_value: FedAdminRole,
  new_value: FedAdminRole,
}


sig EmmState {
  .tag: String,
}


sig DirectoryRestrictionsAddMembersDetails {
}


sig SharedContentUnshareType {
  description: String,
}


sig SharedContentChangeInviteeRoleType {
  description: String,
}


sig SharedFolderChangeMembersInheritancePolicyType {
  description: String,
}


sig MemberSpaceLimitsAddExceptionType {
  description: String,
}


sig TeamMergeRequestCanceledShownToSecondaryTeamType {
  description: String,
}


sig PathOrId {
  // Primitive type: string
  value: String
}


sig ExportResult {
  export_metadata: ExportMetadata,
  file_metadata: FileMetadata,
}


sig TwoAccountPolicy {
  .tag: String,
}


sig ChangeLinkExpirationPolicy {
  .tag: String,
}


sig SaveUrlResult {
  .tag: String,
}


sig PaperContentRemoveMemberType {
  description: String,
}


sig PropertiesSearchError {
  .tag: String,
}


sig DisabledDomainInvitesDetails {
}


sig GracePeriod {
  .tag: String,
}


sig ObjectLabelUpdatedValueType {
  description: String,
}


sig LegalHoldsListPoliciesError {
  .tag: String,
}


sig SharedLinkCreateType {
  description: String,
}


sig PaperDocFollowedDetails {
  event_uuid: String,
}


sig ShowcaseRenamedType {
  description: String,
}


sig EmailIngestPolicy {
  .tag: String,
}


sig AppPermissionsChangedDetails {
  new_value: AdminConsoleAppPolicy,
  previous_value: AdminConsoleAppPolicy,
  app_name: lone String,
  permission: lone AdminConsoleAppPermission,
}


sig GroupCreateArg {
  group_management_type: lone GroupManagementType,
  group_external_id: lone GroupExternalId,
  group_name: String,
  add_creator_as_owner: Bool,
}


sig TeamMergeRequestAcceptedShownToSecondaryTeamDetails {
  sent_by: String,
  primary_team: String,
}


sig CreateFolderError {
  .tag: String,
}


sig FileOrFolderLogInfo {
  path: PathLogInfo,
  display_name: lone String,
  file_size: lone Int,
  file_id: lone String,
}


sig UndoOrganizeFolderWithTidyDetails {
}


sig OutdatedLinkViewReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig SetProfilePhotoResult {
  profile_photo_url: String,
}


sig MemberTransferredInternalFields {
  source_team_id: TeamId,
  target_team_id: TeamId,
}


sig BasicAccount {
  // Generic object with no specific type
}


sig MemberChangeStatusType {
  description: String,
}


sig UploadSessionStartBatchResult {
  session_ids: set String,
}


sig DirectoryRestrictionsRemoveMembersType {
  description: String,
}


sig RewindPolicy {
  .tag: String,
}


sig SharedContentRemoveMemberDetails {
  shared_content_access_level: lone AccessLevel,
}


sig AdminEmailRemindersPolicy {
  .tag: String,
}


sig SmartSyncCreateAdminPrivilegeReportDetails {
}


sig TeamNamespacesListError {
  .tag: String,
}


sig ExportError {
  .tag: String,
}


sig LegalHoldsPolicyCreateResult {
  // Generic object with no specific type
}


sig RelocationBatchErrorEntry {
  .tag: String,
}


sig FileChangeCommentSubscriptionType {
  description: String,
}


sig GetDevicesReport {
  // Generic object with no specific type
}


sig FileEditType {
  description: String,
}


sig SharingChangeLinkPolicyType {
  description: String,
}


sig TeamReportFailureReason {
  .tag: String,
}


sig AdminAlertingChangedAlertConfigType {
  description: String,
}


sig SaveUrlJobStatus {
  .tag: String,
}


sig PaperDocUnresolveCommentType {
  description: String,
}


sig TeamMergeRequestSentShownToSecondaryTeamType {
  description: String,
}


sig ShareFolderArg {
  // Generic object with no specific type
}


sig SsoErrorDetails {
  error_details: FailureDetailsLogInfo,
}


sig FolderSharingInfo {
  // Generic object with no specific type
}


sig PaperContentRenameDetails {
  event_uuid: String,
}


sig RemoveFolderMemberError {
  .tag: String,
}


sig ApplyNamingConventionDetails {
}


sig SharedContentChangeMemberRoleType {
  description: String,
}


sig TfaConfiguration {
  .tag: String,
}


sig PaperPublishedLinkCreateDetails {
  event_uuid: String,
}


sig TwoAccountChangePolicyType {
  description: String,
}


sig TeamFolderListError {
  access_error: TeamFolderAccessError,
}


sig AsyncJobId {
  // Primitive type: string
  value: String
}


sig MediaInfo {
  .tag: String,
}


sig MemberDeleteManualContactsType {
  description: String,
}


sig PreviewResult {
  link_metadata: lone MinimalFileLinkMetadata,
  file_metadata: lone FileMetadata,
}


sig ListDocsCursorError {
  .tag: String,
}


sig EmailIngestReceiveFileType {
  description: String,
}


sig SharedContentChangeViewerInfoPolicyType {
  description: String,
}


sig ChangedEnterpriseConnectedTeamStatusDetails {
  additional_info: FederationStatusChangeAdditionalInfo,
  new_value: TrustedTeamsRequestState,
  action: FedHandshakeAction,
  previous_value: TrustedTeamsRequestState,
}


sig FolderOverviewItemPinnedType {
  description: String,
}


sig PaperDocId {
  // Primitive type: string
  value: String
}


sig ListFolderMembersCursorArg {
  limit: Int,
  actions: lone set MemberAction,
}


sig FolderOverviewDescriptionChangedDetails {
  folder_overview_location_asset: Int,
}


sig UploadSessionOffsetError {
  correct_offset: Int,
}


sig NoteShareReceiveDetails {
}


sig PaperAdminExportStartDetails {
}


sig SmartSyncChangePolicyDetails {
  new_value: lone SmartSyncPolicy,
  previous_value: lone SmartSyncPolicy,
}


sig CreateSharedLinkArg {
  short_url: Bool,
  path: String,
  pending_upload: lone PendingUploadMode,
}


sig TeamMergeRequestExpiredShownToPrimaryTeamDetails {
  sent_by: String,
  secondary_team: String,
}


sig GroupUpdateError {
  .tag: String,
}


sig Date {
  // Primitive type: string
  value: String
}


sig AdminRole {
  .tag: String,
}


sig GroupDeleteType {
  description: String,
}


sig TeamMergeRequestRejectedShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_by: String,
}


sig TeamEncryptionKeyCreateKeyType {
  description: String,
}


sig RelocationBatchArgBase {
  entries: set RelocationPath,
  autorename: Bool,
}


sig MoveBatchArg {
  // Generic object with no specific type
}


sig MemberSuggestType {
  description: String,
}


sig WriteMode {
  .tag: String,
}


sig GroupJoinPolicyUpdatedType {
  description: String,
}


sig EnabledDomainInvitesType {
  description: String,
}


sig TeamFolderCreateError {
  .tag: String,
}


sig FileLockingPolicyState {
  .tag: String,
}


sig SaveCopyReferenceArg {
  path: Path,
  copy_reference: String,
}


sig DeleteBatchError {
  .tag: String,
}


sig SharedFolderChangeMembersPolicyDetails {
  new_value: MemberPolicy,
  previous_value: lone MemberPolicy,
}


sig DeviceManagementDisabledType {
  description: String,
}


sig TfaAddSecurityKeyType {
  description: String,
}


sig ShowcaseUntrashedType {
  description: String,
}


sig SfTeamGrantAccessDetails {
  target_asset_index: Int,
  original_folder_name: String,
}


sig RequestedLinkAccessLevel {
  .tag: String,
}


sig MemberPermission {
  allow: Bool,
  reason: lone PermissionDeniedReason,
  action: MemberAction,
}


sig Certificate {
  issuer: String,
  serial_number: String,
  subject: String,
  common_name: lone String,
  issue_date: String,
  sha1_fingerprint: String,
  expiration_date: String,
}


sig FileEditCommentType {
  description: String,
}


sig NoPasswordLinkViewReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig LegalHoldsPolicyReleaseError {
  .tag: String,
}


sig WatermarkingPolicyChangedDetails {
  new_value: WatermarkingPolicy,
  previous_value: WatermarkingPolicy,
}


sig MemberSpaceLimitsAddCustomQuotaType {
  description: String,
}


sig PaperDocChangeSharingPolicyType {
  description: String,
}


sig PaperDocFollowedType {
  description: String,
}


sig InviteAcceptanceEmailPolicyChangedType {
  description: String,
}


sig SetCustomQuotaArg {
  users_and_quotas: set UserCustomQuotaArg,
}


sig RelocationBatchResultData {
  metadata: Metadata,
}


sig GetAccountArg {
  account_id: AccountId,
}


sig PaperDefaultFolderPolicy {
  .tag: String,
}


sig PaperContentRemoveMemberDetails {
  event_uuid: String,
}


sig TeamFolderIdListArg {
  team_folder_ids: set SharedFolderId,
}


sig DeviceLinkSuccessType {
  description: String,
}


sig SfAllowNonMembersToViewSharedLinksType {
  description: String,
}


sig UploadSessionFinishBatchResult {
  entries: set UploadSessionFinishBatchResultEntry,
}


sig ObjectLabelAddedType {
  description: String,
}


sig PaperChangePolicyType {
  description: String,
}


sig ListMembersDevicesError {
  .tag: String,
}


sig RelocationBatchLaunch {
  .tag: String,
}


sig MembersDeactivateArg {
  // Generic object with no specific type
}


sig RevokeSharedLinkArg {
  url: String,
}


sig RelocationBatchJobStatus {
  .tag: String,
}


sig ShowcaseFileViewType {
  description: String,
}


sig MemberSpaceLimitsRemoveExceptionType {
  description: String,
}


sig MemberDevices {
  team_member_id: String,
  desktop_clients: lone set DesktopClientSession,
  web_sessions: lone set ActiveWebSession,
  mobile_clients: lone set MobileClientSession,
}


sig RemoveFileMemberError {
  .tag: String,
}


sig CreateFolderBatchError {
  .tag: String,
}


sig AddMember {
  member: MemberSelector,
  access_level: AccessLevel,
}


sig ResellerSupportChangePolicyDetails {
  new_value: ResellerSupportPolicy,
  previous_value: ResellerSupportPolicy,
}


sig GroupMembershipInfo {
  // Generic object with no specific type
}


sig AppLinkTeamDetails {
  app_info: AppLogInfo,
}


sig ChangedEnterpriseAdminRoleType {
  description: String,
}


sig SharedFolderChangeMembersInheritancePolicyDetails {
  new_value: SharedFolderMembersInheritancePolicy,
  previous_value: lone SharedFolderMembersInheritancePolicy,
}


sig ThumbnailFormat {
  .tag: String,
}


sig MemberSuggestionsChangePolicyDetails {
  new_value: MemberSuggestionsPolicy,
  previous_value: lone MemberSuggestionsPolicy,
}


sig EchoArg {
  query: String,
}


sig SharingChangeLinkEnforcePasswordPolicyType {
  description: String,
}


sig NetworkControlPolicy {
  .tag: String,
}


sig RelinquishFolderMembershipError {
  .tag: String,
}


sig MemberChangeNameType {
  description: String,
}


// API operations
// Operation: POST /team/members/get_available_team_member_roles
// Get available TeamMemberRoles for the connected team. To be used with :route:`members/set_admin_permissions:2`.
// 
//     Permission : Team member management.
one sig Operation_members/get_available_team_member_roles extends Operation {
  id: members/get_available_team_member_roles,
  path: "/team/members/get_available_team_member_roles",
  method: "POST",
  responses: set Response
}
fact Operation_members/get_available_team_member_roles_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/get_available_team_member_roles.responses
}


// Operation: POST /paper/docs/folder_users/list
// Lists the users who are explicitly invited to the Paper folder in which the Paper doc
//     is contained. For private folders all users (including owner) shared on the folder
//     are listed and for team folders all non-team users shared on the folder are returned.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/folder_users/list extends Operation {
  id: docs/folder_users/list,
  path: "/paper/docs/folder_users/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/folder_users/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/folder_users/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/folder_users/list.responses
}


// Operation: POST /team/members/add/job_status/get
// Once an async_job_id is returned from :route:`members/add` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members/add/job_status/get extends Operation {
  id: members/add/job_status/get,
  path: "/team/members/add/job_status/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/add/job_status/get_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/add/job_status/get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/add/job_status/get.responses
}


// Operation: POST /team/members/move_former_member_files/job_status/check
// Once an async_job_id is returned from :route:`members/move_former_member_files` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members/move_former_member_files/job_status/check extends Operation {
  id: members/move_former_member_files/job_status/check,
  path: "/team/members/move_former_member_files/job_status/check",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/move_former_member_files/job_status/check_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/move_former_member_files/job_status/check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/move_former_member_files/job_status/check.responses
}


// Operation: POST /sharing/list_received_files/continue
// Get more results with a cursor from :route:`list_received_files`.
one sig Operation_list_received_files/continue extends Operation {
  id: list_received_files/continue,
  path: "/sharing/list_received_files/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_received_files/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_received_files/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_received_files/continue.responses
}


// Operation: POST /team/team_folder/list
// Lists all team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/list extends Operation {
  id: team_folder/list,
  path: "/team/team_folder/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/list.responses
}


// Operation: POST /file_properties/templates/add_for_team
// Add a template associated with a team. See :route:`properties/add` to add properties to a file or folder.
// 
//     Note: this endpoint will create team-owned templates.
one sig Operation_templates/add_for_team extends Operation {
  id: templates/add_for_team,
  path: "/file_properties/templates/add_for_team",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/add_for_team_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/add_for_team.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/add_for_team.responses
}


// Operation: POST /team/members/move_former_member_files
// Moves removed member's files to a different member. This endpoint initiates an asynchronous job. To obtain the final result
//     of the job, the client should periodically poll :route:`members/move_former_member_files/job_status/check`.
// 
//     Permission : Team member management.
one sig Operation_members/move_former_member_files extends Operation {
  id: members/move_former_member_files,
  path: "/team/members/move_former_member_files",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/move_former_member_files_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/move_former_member_files.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/move_former_member_files.responses
}


// Operation: POST /sharing/list_file_members/batch
// Get members of multiple files at once. The arguments
//     to this route are more limited, and the limit on query result size per file
//     is more strict. To customize the results more, use the individual file
//     endpoint.
// 
//     Inherited users and groups are not included in the result, and permissions are not
//     returned for this endpoint.
one sig Operation_list_file_members/batch extends Operation {
  id: list_file_members/batch,
  path: "/sharing/list_file_members/batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_file_members/batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members/batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members/batch.responses
}


// Operation: POST /team/linked_apps/list_member_linked_apps
// List all linked applications of the team member.
// 
//     Note, this endpoint does not list any team-linked applications.
one sig Operation_linked_apps/list_member_linked_apps extends Operation {
  id: linked_apps/list_member_linked_apps,
  path: "/team/linked_apps/list_member_linked_apps",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_linked_apps/list_member_linked_apps_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps/list_member_linked_apps.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps/list_member_linked_apps.responses
}


// Operation: POST /files/get_temporary_upload_link
// Get a one-time use temporary upload link to upload a file to a Dropbox location.
// 
// 
//     This endpoint acts as a delayed :route:`upload`. The returned temporary upload link may be used
//     to make a POST request with the data to be uploaded. The upload will then be perfomed with the
//     :type:`CommitInfo` previously provided to :route:`get_temporary_upload_link` but evaluated only
//     upon consumption. Hence, errors stemming from invalid :type:`CommitInfo` with respect to the
//     state of the user's Dropbox will only be communicated at consumption time. Additionally, these
//     errors are surfaced as generic HTTP 409 Conflict responses, potentially hiding issue details.
//     The maximum temporary upload link duration is 4 hours. Upon consumption or expiration,
//     a new link will have to be generated. Multiple links may exist for a specific upload path
//     at any given time.
// 
// 
//     The POST request on the temporary upload link must have its Content-Type
//     set to "application/octet-stream".
// 
// 
//     Example temporary upload link consumption request:
// 
// 
//     curl -X POST https://content.dropboxapi.com/apitul/1/bNi2uIYF51cVBND
// 
//     --header "Content-Type: application/octet-stream"
// 
//     --data-binary @local_file.txt
// 
// 
//     A successful temporary upload link consumption request returns the content hash
//     of the uploaded data in JSON format.
// 
// 
//     Example successful temporary upload link consumption response:
// 
//     {"content-hash": "599d71033d700ac892a0e48fa61b125d2f5994"}
// 
// 
//     An unsuccessful temporary upload link consumption request returns any of the following status
//     codes:
// 
// 
//     HTTP 400 Bad Request: Content-Type is not one of
//     application/octet-stream and text/plain or request is invalid.
// 
//     HTTP 409 Conflict: The temporary upload link does not exist or is currently unavailable,
//     the upload failed, or another error happened.
// 
//     HTTP 410 Gone: The temporary upload link is expired or consumed.
// 
// 
//     Example unsuccessful temporary upload link consumption response:
// 
//     Temporary upload link has been recently consumed.
//     
one sig Operation_get_temporary_upload_link extends Operation {
  id: get_temporary_upload_link,
  path: "/files/get_temporary_upload_link",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_temporary_upload_link_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_temporary_upload_link.responses
}


// Operation: POST /team/member_space_limits/get_custom_quota
// Get users custom quota.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits/get_custom_quota extends Operation {
  id: member_space_limits/get_custom_quota,
  path: "/team/member_space_limits/get_custom_quota",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/get_custom_quota_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/get_custom_quota.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/get_custom_quota.responses
}


// Operation: POST /team/groups/create
// Creates a new, empty group, with a requested name.
// 
//     Permission : Team member management.
one sig Operation_groups/create extends Operation {
  id: groups/create,
  path: "/team/groups/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/create_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/create.responses
}


// Operation: POST /files/upload
// Create a new file with the contents provided in the request. Note that the
//     behavior of this alpha endpoint is unstable and subject to change.
// 
//     Do not use this to upload a file larger than 150 MB. Instead, create an
//     upload session with :route:`upload_session/start`. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_upload extends Operation {
  id: upload,
  path: "/files/upload",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload.responses
}


// Operation: POST /paper/docs/create
// Creates a new Paper doc with the provided content.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_docs/create extends Operation {
  id: docs/create,
  path: "/paper/docs/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/create_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/create.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/create.responses
}


// Operation: POST /team/member_space_limits/excluded_users/list
// List member space limits excluded users.
one sig Operation_member_space_limits/excluded_users/list extends Operation {
  id: member_space_limits/excluded_users/list,
  path: "/team/member_space_limits/excluded_users/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/excluded_users/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/excluded_users/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/excluded_users/list.responses
}


// Operation: POST /file_requests/list
// Returns a list of file requests owned by this user. For apps with the app
//     folder permission, this will only return file requests with destinations in
//     the app folder.
one sig Operation_list extends Operation {
  id: list,
  path: "/file_requests/list",
  method: "POST",
  responses: set Response
}
fact Operation_list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list.responses
}


// Operation: POST /file_properties/templates/remove_for_user
// Permanently removes the specified template created from :route:`templates/add_for_user`.
//     All properties associated with the template will also be removed. This action
//     cannot be undone.
one sig Operation_templates/remove_for_user extends Operation {
  id: templates/remove_for_user,
  path: "/file_properties/templates/remove_for_user",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/remove_for_user_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/remove_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/remove_for_user.responses
}


// Operation: POST /sharing/mount_folder
// The current user mounts the designated folder.
// 
//     Mount a shared folder for a user after they have been added as a member.
//     Once mounted, the shared folder will appear in their Dropbox.
one sig Operation_mount_folder extends Operation {
  id: mount_folder,
  path: "/sharing/mount_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_mount_folder_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_mount_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_mount_folder.responses
}


// Operation: POST /files/create_folder:2
// Create a folder at a given path.
one sig Operation_create_folder:2 extends Operation {
  id: create_folder:2,
  path: "/files/create_folder:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_create_folder:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_folder:2.responses
}


// Operation: POST /files/get_metadata
// Returns the metadata for a file or folder. This is an alpha endpoint
//     compatible with the properties API.
// 
//     Note: Metadata for the root folder is unsupported.
one sig Operation_get_metadata extends Operation {
  id: get_metadata,
  path: "/files/get_metadata",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_metadata_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_metadata.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_metadata.responses
}


// Operation: POST /file_properties/templates/remove_for_team
// Permanently removes the specified template created from :route:`templates/add_for_user`.
//     All properties associated with the template will also be removed. This action
//     cannot be undone.
one sig Operation_templates/remove_for_team extends Operation {
  id: templates/remove_for_team,
  path: "/file_properties/templates/remove_for_team",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/remove_for_team_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/remove_for_team.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/remove_for_team.responses
}


// Operation: POST /team/members/list/continue:2
// Once a cursor has been retrieved from :route:`members/list:2`, use this to paginate
//     through all team members.
// 
//     Permission : Team information.
one sig Operation_members/list/continue:2 extends Operation {
  id: members/list/continue:2,
  path: "/team/members/list/continue:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/list/continue:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/list/continue:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/list/continue:2.responses
}


// Operation: POST /sharing/list_received_files
// Returns a list of all files shared with current user.
// 
//      Does not include files the user has received via shared folders, and does
//      not include unclaimed invitations.
one sig Operation_list_received_files extends Operation {
  id: list_received_files,
  path: "/sharing/list_received_files",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_received_files_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_received_files.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_received_files.responses
}


// Operation: POST /users/get_account_batch
// Get information about multiple user accounts.  At most 300 accounts may be queried
//     per request.
one sig Operation_get_account_batch extends Operation {
  id: get_account_batch,
  path: "/users/get_account_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_account_batch_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_account_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_account_batch.responses
}


// Operation: POST /team/groups/list/continue
// Once a cursor has been retrieved from :route:`groups/list`, use this to paginate
//     through all groups.
// 
//     Permission : Team Information.
one sig Operation_groups/list/continue extends Operation {
  id: groups/list/continue,
  path: "/team/groups/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/list/continue.responses
}


// Operation: POST /team/team_folder/archive/check
// Returns the status of an asynchronous job for archiving a team folder.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/archive/check extends Operation {
  id: team_folder/archive/check,
  path: "/team/team_folder/archive/check",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/archive/check_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/archive/check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/archive/check.responses
}


// Operation: POST /team/legal_holds/list_held_revisions_continue
// Continue listing the file metadata that's under the hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/list_held_revisions_continue extends Operation {
  id: legal_holds/list_held_revisions_continue,
  path: "/team/legal_holds/list_held_revisions_continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/list_held_revisions_continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/list_held_revisions_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/list_held_revisions_continue.responses
}


// Operation: POST /team/properties/template/list
// Permission : Team member file access. The scope for the route is files.team_metadata.write.
one sig Operation_properties/template/list extends Operation {
  id: properties/template/list,
  path: "/team/properties/template/list",
  method: "POST",
  responses: set Response
}
fact Operation_properties/template/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/list.responses
}


// Operation: POST /team/members/set_admin_permissions:2
// Updates a team member's permissions.
// 
//     Permission : Team member management.
one sig Operation_members/set_admin_permissions:2 extends Operation {
  id: members/set_admin_permissions:2,
  path: "/team/members/set_admin_permissions:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_admin_permissions:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_admin_permissions:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_admin_permissions:2.responses
}


// Operation: POST /files/list_folder/continue
// Once a cursor has been retrieved from :route:`list_folder`, use this to paginate through all
//     files and retrieve updates to the folder, following the same rules as documented for
//     :route:`list_folder`.
one sig Operation_list_folder/continue extends Operation {
  id: list_folder/continue,
  path: "/files/list_folder/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder/continue.responses
}


// Operation: POST /files/upload_session/finish_batch:2
// This route helps you commit many files at once into a user's Dropbox. Use
//     :route:`upload_session/start` and :route:`upload_session/append:2` to
//     upload file contents. We recommend uploading many files in parallel to increase
//     throughput. Once the file contents have been uploaded, rather than calling
//     :route:`upload_session/finish`, use this route to finish all your upload sessions
//     in a single request.
// 
//     :field:`UploadSessionStartArg.close` or :field:`UploadSessionAppendArg.close`
//     needs to be true for the last
//     :route:`upload_session/start` or :route:`upload_session/append:2` call of each upload session. The maximum
//     size of a file one can upload to an upload session is 350 GB.
// 
//     We allow up to 1000 entries in a single request.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page https://www.dropbox.com/developers/reference/data-transport-limit`.
one sig Operation_upload_session/finish_batch:2 extends Operation {
  id: upload_session/finish_batch:2,
  path: "/files/upload_session/finish_batch:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/finish_batch:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/finish_batch:2.responses
}


// Operation: POST /account/set_profile_photo
// Sets a user's profile photo.
one sig Operation_set_profile_photo extends Operation {
  id: set_profile_photo,
  path: "/account/set_profile_photo",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_set_profile_photo_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_set_profile_photo.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_set_profile_photo.responses
}


// Operation: POST /team/properties/template/add
// Permission : Team member file access.
one sig Operation_properties/template/add extends Operation {
  id: properties/template/add,
  path: "/team/properties/template/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/template/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/add.responses
}


// Operation: POST /sharing/list_mountable_folders
// Return the list of all shared folders the current user can mount or unmount.
one sig Operation_list_mountable_folders extends Operation {
  id: list_mountable_folders,
  path: "/sharing/list_mountable_folders",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_mountable_folders_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_mountable_folders.responses
}


// Operation: POST /sharing/list_file_members
// Use to obtain the members who have been invited to a file, both inherited
//     and uninherited members.
one sig Operation_list_file_members extends Operation {
  id: list_file_members,
  path: "/sharing/list_file_members",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_file_members_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members.responses
}


// Operation: POST /file_requests/create
// Creates a file request for this user.
one sig Operation_create extends Operation {
  id: create,
  path: "/file_requests/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_create_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create.responses
}


// Operation: POST /files/download_zip
// Download a folder from the user's Dropbox, as a zip file. The folder must be less than 20 GB
//     in size and any single file within must be less than 4 GB in size. The resulting zip must have
//     fewer than 10,000 total file and folder entries, including the top level folder. The input
//     cannot be a single file.
// 
//     Note: this endpoint does not support HTTP range requests. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_download_zip extends Operation {
  id: download_zip,
  path: "/files/download_zip",
  method: "POST",
  responses: set Response
}
fact Operation_download_zip_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_download_zip.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_download_zip.responses
}


// Operation: POST /team/devices/list_members_devices
// List all device sessions of a team.
// 
//     Permission : Team member file access.
one sig Operation_devices/list_members_devices extends Operation {
  id: devices/list_members_devices,
  path: "/team/devices/list_members_devices",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_devices/list_members_devices_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices/list_members_devices.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices/list_members_devices.responses
}


// Operation: POST /team/reports/get_membership
// Retrieves reporting data about a team's membership.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports/get_membership extends Operation {
  id: reports/get_membership,
  path: "/team/reports/get_membership",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_reports/get_membership_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports/get_membership.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports/get_membership.responses
}


// Operation: POST /sharing/add_file_member
// Adds specified members to a file.
one sig Operation_add_file_member extends Operation {
  id: add_file_member,
  path: "/sharing/add_file_member",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_add_file_member_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_add_file_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_add_file_member.responses
}


// Operation: POST /file_properties/templates/update_for_team
// Update a template associated with a team. This route can update the template name,
//     the template description and add optional properties to templates.
one sig Operation_templates/update_for_team extends Operation {
  id: templates/update_for_team,
  path: "/file_properties/templates/update_for_team",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/update_for_team_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/update_for_team.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/update_for_team.responses
}


// Operation: POST /team/members/remove/job_status/get
// Once an async_job_id is returned from :route:`members/remove` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members/remove/job_status/get extends Operation {
  id: members/remove/job_status/get,
  path: "/team/members/remove/job_status/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/remove/job_status/get_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/remove/job_status/get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/remove/job_status/get.responses
}


// Operation: POST /team/team_folder/update_sync_settings
// Updates the sync settings on a team folder or its contents.  Use of this endpoint requires that the team has team selective sync enabled.
one sig Operation_team_folder/update_sync_settings extends Operation {
  id: team_folder/update_sync_settings,
  path: "/team/team_folder/update_sync_settings",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/update_sync_settings_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/update_sync_settings.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/update_sync_settings.responses
}


// Operation: POST /files/get_thumbnail_batch
// Get thumbnails for a list of images. We allow up to 25 thumbnails in a single batch.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail.
one sig Operation_get_thumbnail_batch extends Operation {
  id: get_thumbnail_batch,
  path: "/files/get_thumbnail_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_thumbnail_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail_batch.responses
}


// Operation: POST /file_properties/templates/get_for_team
// Get the schema for a specified template.
one sig Operation_templates/get_for_team extends Operation {
  id: templates/get_for_team,
  path: "/file_properties/templates/get_for_team",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/get_for_team_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/get_for_team.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/get_for_team.responses
}


// Operation: POST /team/members/recover
// Recover a deleted member.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members/recover extends Operation {
  id: members/recover,
  path: "/team/members/recover",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/recover_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/recover.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/recover.responses
}


// Operation: POST /team/namespaces/list
// Returns a list of all team-accessible namespaces. This list includes team folders,
//     shared folders containing team members, team members' home namespaces, and team members'
//     app folders. Home namespaces and app folders are always owned by this team or members of the
//     team, but shared folders may be owned by other users or other teams. Duplicates may occur in the
//     list.
one sig Operation_namespaces/list extends Operation {
  id: namespaces/list,
  path: "/team/namespaces/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_namespaces/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_namespaces/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_namespaces/list.responses
}


// Operation: POST /sharing/list_folders/continue
// Once a cursor has been retrieved from :route:`list_folders`, use this to paginate through all
//     shared folders. The cursor must come from a previous call to :route:`list_folders` or
//     :route:`list_folders/continue`.
one sig Operation_list_folders/continue extends Operation {
  id: list_folders/continue,
  path: "/sharing/list_folders/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folders/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folders/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folders/continue.responses
}


// Operation: POST /team/member_space_limits/excluded_users/list/continue
// Continue listing member space limits excluded users.
one sig Operation_member_space_limits/excluded_users/list/continue extends Operation {
  id: member_space_limits/excluded_users/list/continue,
  path: "/team/member_space_limits/excluded_users/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/excluded_users/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/excluded_users/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/excluded_users/list/continue.responses
}


// Operation: POST /files/upload_session/append:2
// Append more data to an upload session.
// 
//     A single request should not upload more than 150 MB. The maximum size of
//     a file one can upload to an upload session is 350 GB.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page https://www.dropbox.com/developers/reference/data-transport-limit`. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_upload_session/append:2 extends Operation {
  id: upload_session/append:2,
  path: "/files/upload_session/append:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/append:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session/append:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/append:2.responses
}


// Operation: POST /files/delete_batch
// Delete multiple files/folders at once.
// 
//     This route is asynchronous, which returns a job ID immediately and runs
//     the delete batch asynchronously. Use :route:`delete_batch/check` to check
//     the job status.
one sig Operation_delete_batch extends Operation {
  id: delete_batch,
  path: "/files/delete_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_delete_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_batch.responses
}


// Operation: POST /file_requests/update
// Update a file request.
one sig Operation_update extends Operation {
  id: update,
  path: "/file_requests/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_update_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update.responses
}


// Operation: POST /openid/userinfo
// This route is used for refreshing the info that is found in the id_token during the OIDC flow.
//     This route doesn't require any arguments and will use the scopes approved for the given access token.
one sig Operation_userinfo extends Operation {
  id: userinfo,
  path: "/openid/userinfo",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_userinfo_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_userinfo.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_userinfo.responses
}


// Operation: POST /users/get_account
// Get information about a user's account.
one sig Operation_get_account extends Operation {
  id: get_account,
  path: "/users/get_account",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_account_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_account.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_account.responses
}


// Operation: POST /team/reports/get_devices
// Retrieves reporting data about a team's linked devices.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports/get_devices extends Operation {
  id: reports/get_devices,
  path: "/team/reports/get_devices",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_reports/get_devices_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports/get_devices.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports/get_devices.responses
}


// Operation: POST /files/upload_session/start_batch
// This route starts batch of upload_sessions. Please refer to `upload_session/start` usage.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page
//     https://www.dropbox.com/developers/reference/data-transport-limit`. RPC-style endpoint: Both request and response bodies are JSON.
one sig Operation_upload_session/start_batch extends Operation {
  id: upload_session/start_batch,
  path: "/files/upload_session/start_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/start_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/start_batch.responses
}


// Operation: POST /files/download
// Download a file from a user's Dropbox. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_download extends Operation {
  id: download,
  path: "/files/download",
  method: "POST",
  responses: set Response
}
fact Operation_download_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_download.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_download.responses
}


// Operation: POST /files/properties/remove
// Execute properties/remove
one sig Operation_properties/remove extends Operation {
  id: properties/remove,
  path: "/files/properties/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/remove.responses
}


// Operation: POST /team/sharing_allowlist/remove
// Endpoint removes Approve List entries. Changes are effective immediately.
//     Changes are committed in transaction. In case of single validation error - all entries are rejected.
//     Valid domains (RFC-1034/5) and emails (RFC-5322/822) are accepted.
//     Entries being removed have to be present on the list.
//     Maximum 1000 entries per call is allowed.
one sig Operation_sharing_allowlist/remove extends Operation {
  id: sharing_allowlist/remove,
  path: "/team/sharing_allowlist/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_sharing_allowlist/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist/remove.responses
}


// Operation: POST /team/legal_holds/create_policy
// Creates new legal hold policy.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/create_policy extends Operation {
  id: legal_holds/create_policy,
  path: "/team/legal_holds/create_policy",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/create_policy_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/create_policy.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/create_policy.responses
}


// Operation: POST /team/devices/revoke_device_session_batch
// Revoke a list of device sessions of team members.
one sig Operation_devices/revoke_device_session_batch extends Operation {
  id: devices/revoke_device_session_batch,
  path: "/team/devices/revoke_device_session_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_devices/revoke_device_session_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices/revoke_device_session_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices/revoke_device_session_batch.responses
}


// Operation: POST /sharing/list_shared_links
// Returns a list of :type:`LinkMetadata` objects for this user,
//     including collection links.
// 
//     If no path is given, returns a list of all shared links for the current
//     user, including collection links, up to a maximum of 1000 links.
// 
//     If a non-empty path is given, returns a list of all shared links
//     that allow access to the given path.  Collection links are never
//     returned in this case.
one sig Operation_list_shared_links extends Operation {
  id: list_shared_links,
  path: "/sharing/list_shared_links",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_shared_links_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_shared_links.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_shared_links.responses
}


// Operation: POST /sharing/add_folder_member
// Allows an owner or editor (if the ACL update policy allows) of a shared
//     folder to add another member.
// 
//     For the new member to get access to all the functionality for this folder,
//     you will need to call :route:`mount_folder` on their behalf.
one sig Operation_add_folder_member extends Operation {
  id: add_folder_member,
  path: "/sharing/add_folder_member",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_add_folder_member_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_add_folder_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_add_folder_member.responses
}


// Operation: POST /files/save_url/check_job_status
// Check the status of a :route:`save_url` job.
one sig Operation_save_url/check_job_status extends Operation {
  id: save_url/check_job_status,
  path: "/files/save_url/check_job_status",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_save_url/check_job_status_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_save_url/check_job_status.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_save_url/check_job_status.responses
}


// Operation: POST /sharing/create_shared_link_with_settings
// Create a shared link.
// 
//     If a shared link already exists for the given path, that link is returned.
// 
//     Previously, it was technically possible to break a shared link by moving or
//     renaming the corresponding file or folder. In the future, this will no
//     longer be the case, so your app shouldn't rely on this behavior. Instead, if
//     your app needs to revoke a shared link, use :route:`revoke_shared_link`.
one sig Operation_create_shared_link_with_settings extends Operation {
  id: create_shared_link_with_settings,
  path: "/sharing/create_shared_link_with_settings",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_create_shared_link_with_settings_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_shared_link_with_settings.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_shared_link_with_settings.responses
}


// Operation: POST /team/members/send_welcome_email
// Sends welcome email to pending team member.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
// 
//     No-op if team member is not pending.
one sig Operation_members/send_welcome_email extends Operation {
  id: members/send_welcome_email,
  path: "/team/members/send_welcome_email",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/send_welcome_email_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/send_welcome_email.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/send_welcome_email.responses
}


// Operation: POST /files/move_batch/check:2
// Returns the status of an asynchronous job for :route:`move_batch:1`. If
//     success, it returns list of results for each entry.
one sig Operation_move_batch/check:2 extends Operation {
  id: move_batch/check:2,
  path: "/files/move_batch/check:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_move_batch/check:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move_batch/check:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_move_batch/check:2.responses
}


// Operation: POST /file_properties/properties/search/continue
// Once a cursor has been retrieved from :route:`properties/search`, use this to paginate through all
//     search results.
one sig Operation_properties/search/continue extends Operation {
  id: properties/search/continue,
  path: "/file_properties/properties/search/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/search/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/search/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/search/continue.responses
}


// Operation: POST /team/features/get_values
// Get the values for one or more featues. This route allows you to check your account's
//     capability for what feature you can access or what value you have for certain features.
// 
//     Permission : Team information.
one sig Operation_features/get_values extends Operation {
  id: features/get_values,
  path: "/team/features/get_values",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_features/get_values_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_features/get_values.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_features/get_values.responses
}


// Operation: POST /sharing/update_folder_member
// Allows an owner or editor of a shared folder to update another member's
//     permissions.
one sig Operation_update_folder_member extends Operation {
  id: update_folder_member,
  path: "/sharing/update_folder_member",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_update_folder_member_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_folder_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_folder_member.responses
}


// Operation: POST /files/get_thumbnail
// Get a thumbnail for an image.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_thumbnail extends Operation {
  id: get_thumbnail,
  path: "/files/get_thumbnail",
  method: "POST",
  responses: set Response
}
fact Operation_get_thumbnail_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail.responses
}


// Operation: POST /file_properties/templates/add_for_user
// Add a template associated with a user. See :route:`properties/add` to add properties to a file. This
//     endpoint can't be called on a team member or admin's behalf.
one sig Operation_templates/add_for_user extends Operation {
  id: templates/add_for_user,
  path: "/file_properties/templates/add_for_user",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/add_for_user_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/add_for_user.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/add_for_user.responses
}


// Operation: POST /auth/token/revoke
// Disables the access token used to authenticate the call.
//     If there is a corresponding refresh token for the access token,
//     this disables that refresh token, as well as any other access tokens for that refresh token.
one sig Operation_token/revoke extends Operation {
  id: token/revoke,
  path: "/auth/token/revoke",
  method: "POST",
  responses: set Response
}
fact Operation_token/revoke_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token/revoke.responses
}


// Operation: POST /team/groups/members/remove
// Removes members from a group.
// 
//     The members are removed immediately. However the revoking of group-owned resources
//     may take additional time.
//     Use the :route:`groups/job_status/get` to determine whether this process has completed.
// 
//     This method permits removing the only owner of a group, even in cases where this is not
//     possible via the web client.
// 
//     Permission : Team member management.
one sig Operation_groups/members/remove extends Operation {
  id: groups/members/remove,
  path: "/team/groups/members/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/members/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/members/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/members/remove.responses
}


// Operation: POST /team/team_folder/get_info
// Retrieves metadata for team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/get_info extends Operation {
  id: team_folder/get_info,
  path: "/team/team_folder/get_info",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/get_info_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/get_info.responses
}


// Operation: POST /file_properties/templates/update_for_user
// Update a template associated with a user. This route can update the template name,
//     the template description and add optional properties to templates. This endpoint can't
//     be called on a team member or admin's behalf.
one sig Operation_templates/update_for_user extends Operation {
  id: templates/update_for_user,
  path: "/file_properties/templates/update_for_user",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/update_for_user_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/update_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/update_for_user.responses
}


// Operation: POST /team/team_folder/permanently_delete
// Permanently deletes an archived team folder. This endpoint cannot be used for teams
//     that have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/permanently_delete extends Operation {
  id: team_folder/permanently_delete,
  path: "/team/team_folder/permanently_delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/permanently_delete_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/permanently_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/permanently_delete.responses
}


// Operation: POST /team/token/get_authenticated_admin
// Returns the member profile of the admin who generated the team access token used to make the call.
one sig Operation_token/get_authenticated_admin extends Operation {
  id: token/get_authenticated_admin,
  path: "/team/token/get_authenticated_admin",
  method: "POST",
  responses: set Response
}
fact Operation_token/get_authenticated_admin_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_token/get_authenticated_admin.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token/get_authenticated_admin.responses
}


// Operation: POST /sharing/revoke_shared_link
// Revoke a shared link.
// 
//     Note that even after revoking a shared link to a file, the file may be accessible if there are
//     shared links leading to any of the file parent folders. To list all shared links that enable
//     access to a specific file, you can use the :route:`list_shared_links` with the file as the
//     :field:`ListSharedLinksArg.path` argument.
one sig Operation_revoke_shared_link extends Operation {
  id: revoke_shared_link,
  path: "/sharing/revoke_shared_link",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_revoke_shared_link_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_revoke_shared_link.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_revoke_shared_link.responses
}


// Operation: POST /files/create_folder_batch
// Create multiple folders at once.
// 
//     This route is asynchronous for large batches, which returns a job ID immediately and runs
//     the create folder batch asynchronously. Otherwise, creates the folders and returns the result
//     synchronously for smaller inputs. You can force asynchronous behaviour by using the
//     :field:`CreateFolderBatchArg.force_async` flag.  Use :route:`create_folder_batch/check` to check
//     the job status.
one sig Operation_create_folder_batch extends Operation {
  id: create_folder_batch,
  path: "/files/create_folder_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_create_folder_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder_batch.responses
}


// Operation: POST /team/team_folder/list/continue
// Once a cursor has been retrieved from :route:`team_folder/list`, use this to paginate
//     through all team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/list/continue extends Operation {
  id: team_folder/list/continue,
  path: "/team/team_folder/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/list/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/list/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/list/continue.responses
}


// Operation: POST /team/linked_apps/revoke_linked_app
// Revoke a linked application of the team member.
one sig Operation_linked_apps/revoke_linked_app extends Operation {
  id: linked_apps/revoke_linked_app,
  path: "/team/linked_apps/revoke_linked_app",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_linked_apps/revoke_linked_app_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps/revoke_linked_app.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps/revoke_linked_app.responses
}


// Operation: POST /team/members/set_admin_permissions
// Updates a team member's permissions.
// 
//     Permission : Team member management.
one sig Operation_members/set_admin_permissions extends Operation {
  id: members/set_admin_permissions,
  path: "/team/members/set_admin_permissions",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_admin_permissions_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_admin_permissions.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_admin_permissions.responses
}


// Operation: POST /sharing/share_folder
// Share a folder with collaborators.
// 
//     Most sharing will be completed synchronously. Large folders will be
//     completed asynchronously. To make testing the async case repeatable, set
//     `ShareFolderArg.force_async`.
// 
//     If a :field:`ShareFolderLaunch.async_job_id` is returned, you'll need to
//     call :route:`check_share_job_status` until the action completes to get the
//     metadata for the folder.
one sig Operation_share_folder extends Operation {
  id: share_folder,
  path: "/sharing/share_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_share_folder_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_share_folder.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_share_folder.responses
}


// Operation: POST /team/members/secondary_emails/resend_verification_emails
// Resend secondary email verification emails.
// 
//     Permission : Team member management.
one sig Operation_members/secondary_emails/resend_verification_emails extends Operation {
  id: members/secondary_emails/resend_verification_emails,
  path: "/team/members/secondary_emails/resend_verification_emails",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/secondary_emails/resend_verification_emails_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/secondary_emails/resend_verification_emails.responses
}


// Operation: POST /paper/docs/list
// Return the list of all Paper docs according to the argument specifications. To iterate
//     over through the full pagination, pass the cursor to :route:`docs/list/continue`.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/list extends Operation {
  id: docs/list,
  path: "/paper/docs/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/list.responses
}


// Operation: POST /paper/docs/permanently_delete
// Permanently deletes the given Paper doc. This operation is final as the doc
//     cannot be recovered.
// 
//     This action can be performed only by the doc owner.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/permanently_delete extends Operation {
  id: docs/permanently_delete,
  path: "/paper/docs/permanently_delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/permanently_delete_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/permanently_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/permanently_delete.responses
}


// Operation: POST /team/reports/get_activity
// Retrieves reporting data about a team's user activity.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports/get_activity extends Operation {
  id: reports/get_activity,
  path: "/team/reports/get_activity",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_reports/get_activity_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports/get_activity.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports/get_activity.responses
}


// Operation: POST /files/get_preview
// Get a preview for a file.
// 
//     Currently, PDF previews are generated for files with the following extensions:
//     .ai, .doc, .docm, .docx, .eps, .gdoc, .gslides, .odp, .odt, .pps, .ppsm, .ppsx, .ppt, .pptm, .pptx, .rtf.
// 
//     HTML previews are generated for files with the following extensions: .csv, .ods, .xls, .xlsm, .gsheet, .xlsx.
// 
//     Other formats will return an unsupported extension error. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_preview extends Operation {
  id: get_preview,
  path: "/files/get_preview",
  method: "POST",
  responses: set Response
}
fact Operation_get_preview_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_preview.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_preview.responses
}


// Operation: POST /team_log/get_events
// Retrieves team events. If the result's :field:`GetTeamEventsResult.has_more` field is
//     :val:`true`, call :route:`get_events/continue` with the returned cursor to retrieve
//     more entries. If end_time is not specified in your request, you may use the returned cursor to
//     poll :route:`get_events/continue` for new events.
// 
//     Many attributes note 'may be missing due to historical data gap'.
// 
//     Note that the file_operations category and & analogous paper events are not available on all
//     Dropbox Business :link:`plans /business/plans-comparison`.
//     Use :link:`features/get_values /developers/documentation/http/teams#team-features-get_values`
//     to check for this feature.
// 
//     Permission : Team Auditing.
one sig Operation_get_events extends Operation {
  id: get_events,
  path: "/team_log/get_events",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_events_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_events.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_events.responses
}


// Operation: POST /file_properties/templates/list_for_team
// Get the template identifiers for a team. To get the schema of
//     each template use :route:`templates/get_for_team`.
one sig Operation_templates/list_for_team extends Operation {
  id: templates/list_for_team,
  path: "/file_properties/templates/list_for_team",
  method: "POST",
  responses: set Response
}
fact Operation_templates/list_for_team_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/list_for_team.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/list_for_team.responses
}


// Operation: POST /team/groups/members/list/continue
// Once a cursor has been retrieved from :route:`groups/members/list`, use this to paginate
//     through all members of the group.
// 
//     Permission : Team information.
one sig Operation_groups/members/list/continue extends Operation {
  id: groups/members/list/continue,
  path: "/team/groups/members/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/members/list/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/members/list/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/members/list/continue.responses
}


// Operation: POST /team/team_folder/rename
// Changes an active team folder's name.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/rename extends Operation {
  id: team_folder/rename,
  path: "/team/team_folder/rename",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/rename_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/rename.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/rename.responses
}


// Operation: POST /file_requests/delete_all_closed
// Delete all closed file requests owned by this user.
one sig Operation_delete_all_closed extends Operation {
  id: delete_all_closed,
  path: "/file_requests/delete_all_closed",
  method: "POST",
  responses: set Response
}
fact Operation_delete_all_closed_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_all_closed.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_all_closed.responses
}


// Operation: POST /files/unlock_file_batch
// 
//     Unlock the files at the given paths. A locked file can only be unlocked by the lock holder
//     or, if a business account, a team admin. A successful response indicates that the file has
//     been unlocked. Returns a list of the unlocked file paths and their metadata after
//     this operation.
//     
one sig Operation_unlock_file_batch extends Operation {
  id: unlock_file_batch,
  path: "/files/unlock_file_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_unlock_file_batch_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unlock_file_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unlock_file_batch.responses
}


// Operation: POST /files/tags/remove
// Remove a tag from an item.
one sig Operation_tags/remove extends Operation {
  id: tags/remove,
  path: "/files/tags/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_tags/remove_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags/remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags/remove.responses
}


// Operation: POST /sharing/list_folder_members
// Returns shared folder membership by its folder ID.
one sig Operation_list_folder_members extends Operation {
  id: list_folder_members,
  path: "/sharing/list_folder_members",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder_members_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_members.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_members.responses
}


// Operation: POST /team/properties/template/get
// Permission : Team member file access. The scope for the route is files.team_metadata.write.
one sig Operation_properties/template/get extends Operation {
  id: properties/template/get,
  path: "/team/properties/template/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/template/get_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/get.responses
}


// Operation: POST /files/delete:2
// Delete the file or folder at a given path.
// 
//     If the path is a folder, all its contents will be deleted too.
// 
//     A successful response indicates that the file or folder was deleted. The returned metadata will
//     be the corresponding :type:`FileMetadata` or :type:`FolderMetadata` for the item at time of
//     deletion, and not a :type:`DeletedMetadata` object.
one sig Operation_delete:2 extends Operation {
  id: delete:2,
  path: "/files/delete:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_delete:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete:2.responses
}


// Operation: POST /team/legal_holds/get_policy
// Gets a legal hold by Id.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/get_policy extends Operation {
  id: legal_holds/get_policy,
  path: "/team/legal_holds/get_policy",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/get_policy_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/get_policy.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/get_policy.responses
}


// Operation: POST /team/linked_apps/revoke_linked_app_batch
// Revoke a list of linked applications of the team members.
one sig Operation_linked_apps/revoke_linked_app_batch extends Operation {
  id: linked_apps/revoke_linked_app_batch,
  path: "/team/linked_apps/revoke_linked_app_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_linked_apps/revoke_linked_app_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps/revoke_linked_app_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps/revoke_linked_app_batch.responses
}


// Operation: POST /files/list_folder
// Starts returning the contents of a folder. If the result's :field:`ListFolderResult.has_more`
//     field is :val:`true`, call :route:`list_folder/continue` with the returned
//     :field:`ListFolderResult.cursor` to retrieve more entries.
// 
//     If you're using :field:`ListFolderArg.recursive` set to :val:`true` to keep a local cache of
//     the contents of a Dropbox account, iterate through each entry in order and process them as
//     follows to keep your local state in sync:
// 
//     For each :type:`FileMetadata`, store the new entry at the given path in your local state. If the
//     required parent folders don't exist yet, create them. If there's already something else at the
//     given path, replace it and remove all its children.
// 
//     For each :type:`FolderMetadata`, store the new entry at the given path in your local state. If
//     the required parent folders don't exist yet, create them. If there's already something else at
//     the given path, replace it but leave the children as they are. Check the new entry's
//     :field:`FolderSharingInfo.read_only` and set all its children's read-only statuses to match.
// 
//     For each :type:`DeletedMetadata`, if your local state has something at the given path, remove it
//     and all its children. If there's nothing at the given path, ignore this entry.
// 
//     Note: :type:`auth.RateLimitError` may be returned if multiple :route:`list_folder` or
//     :route:`list_folder/continue` calls with same parameters are made simultaneously by same
//     API app for same user. If your app implements retry logic, please hold off the retry until
//     the previous request finishes.
one sig Operation_list_folder extends Operation {
  id: list_folder,
  path: "/files/list_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder.responses
}


// Operation: POST /files/upload_session/start
// Upload sessions allow you to upload a single file in one or more
//     requests, for example where the size of the file is greater than 150
//     MB.  This call starts a new upload session with the given data. You
//     can then use :route:`upload_session/append:2` to add more data and
//     :route:`upload_session/finish` to save all the data to a file in
//     Dropbox.
// 
//     A single request should not upload more than 150 MB. The maximum size of
//     a file one can upload to an upload session is 350 GB.
// 
//     An upload session can be used for a maximum of 7 days. Attempting
//     to use an :field:`UploadSessionStartResult.session_id` with
//     :route:`upload_session/append:2` or :route:`upload_session/finish` more
//     than 7 days after its creation will return a
//     :field:`UploadSessionLookupError.not_found`.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page
//     https://www.dropbox.com/developers/reference/data-transport-limit`.
// 
//     By default, upload sessions require you to send content of the file in sequential order via
//     consecutive :route:`upload_session/start`, :route:`upload_session/append:2`,
//     :route:`upload_session/finish` calls. For better performance, you can instead optionally use
//     a :field:`UploadSessionType.concurrent` upload session. To start a new concurrent session,
//     set :field:`UploadSessionStartArg.session_type` to :field:`UploadSessionType.concurrent`.
//     After that, you can send file data in concurrent :route:`upload_session/append:2` requests.
//     Finally finish the session with :route:`upload_session/finish`.
// 
//     There are couple of constraints with concurrent sessions to make them work. You can not send
//     data with :route:`upload_session/start` or :route:`upload_session/finish` call, only with
//     :route:`upload_session/append:2` call. Also data uploaded in :route:`upload_session/append:2`
//     call must be multiple of 4194304 bytes (except for last :route:`upload_session/append:2` with
//     :field:`UploadSessionStartArg.close` to :val:`true`, that may contain any remaining data). Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_upload_session/start extends Operation {
  id: upload_session/start,
  path: "/files/upload_session/start",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/start_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/start.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session/start.responses
}


// Operation: POST /team/team_folder/activate
// Sets an archived team folder's status to active.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/activate extends Operation {
  id: team_folder/activate,
  path: "/team/team_folder/activate",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/activate_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/activate.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/activate.responses
}


// Operation: POST /paper/docs/sharing_policy/set
// Sets the default sharing policy for the given Paper doc. The default 'team_sharing_policy'
//     can be changed only by teams, omit this field for personal accounts.
// 
//     The 'public_sharing_policy' policy can't be set to the value 'disabled' because this setting
//     can be changed only via the team admin console.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/sharing_policy/set extends Operation {
  id: docs/sharing_policy/set,
  path: "/paper/docs/sharing_policy/set",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/sharing_policy/set_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/sharing_policy/set.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/sharing_policy/set.responses
}


// Operation: POST /team/sharing_allowlist/add
// Endpoint adds Approve List entries. Changes are effective immediately.
//     Changes are committed in transaction. In case of single validation error - all entries are rejected.
//     Valid domains (RFC-1034/5) and emails (RFC-5322/822) are accepted.
//     Added entries cannot overflow limit of 10000 entries per team.
//     Maximum 100 entries per call is allowed.
one sig Operation_sharing_allowlist/add extends Operation {
  id: sharing_allowlist/add,
  path: "/team/sharing_allowlist/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_sharing_allowlist/add_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist/add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist/add.responses
}


// Operation: POST /team/members/set_profile
// Updates a team member's profile.
// 
//     Permission : Team member management.
one sig Operation_members/set_profile extends Operation {
  id: members/set_profile,
  path: "/team/members/set_profile",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_profile_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_profile.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_profile.responses
}


// Operation: POST /files/tags/add
// Add a tag to an item. A tag is a string. The strings are automatically converted to lowercase letters. No more than 20 tags can be added to a given item.
one sig Operation_tags/add extends Operation {
  id: tags/add,
  path: "/files/tags/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_tags/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags/add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags/add.responses
}


// Operation: POST /team/properties/template/update
// Permission : Team member file access.
one sig Operation_properties/template/update extends Operation {
  id: properties/template/update,
  path: "/team/properties/template/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/template/update_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/update.responses
}


// Operation: POST /team/legal_holds/update_policy
// Updates a legal hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/update_policy extends Operation {
  id: legal_holds/update_policy,
  path: "/team/legal_holds/update_policy",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/update_policy_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/update_policy.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/update_policy.responses
}


// Operation: POST /files/properties/add
// Execute properties/add
one sig Operation_properties/add extends Operation {
  id: properties/add,
  path: "/files/properties/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/add_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/add.responses
}


// Operation: POST /team/members/get_info
// Returns information about multiple team members.
// 
//     Permission : Team information
// 
//     This endpoint will return :field:`MembersGetInfoItem.id_not_found`,
//     for IDs (or emails) that cannot be matched to a valid team member.
one sig Operation_members/get_info extends Operation {
  id: members/get_info,
  path: "/team/members/get_info",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/get_info_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/get_info.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/get_info.responses
}


// Operation: POST /sharing/get_shared_link_metadata
// Get the shared link's metadata.
one sig Operation_get_shared_link_metadata extends Operation {
  id: get_shared_link_metadata,
  path: "/sharing/get_shared_link_metadata",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_shared_link_metadata_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_shared_link_metadata.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_shared_link_metadata.responses
}


// Operation: POST /team/members/set_profile_photo
// Updates a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members/set_profile_photo extends Operation {
  id: members/set_profile_photo,
  path: "/team/members/set_profile_photo",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_profile_photo_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_profile_photo.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_profile_photo.responses
}


// Operation: POST /files/copy:2
// Copy a file or folder to a different location in the user's Dropbox.
// 
//     If the source path is a folder all its contents will be copied.
one sig Operation_copy:2 extends Operation {
  id: copy:2,
  path: "/files/copy:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_copy:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy:2.responses
}


// Operation: POST /paper/docs/list/continue
// Once a cursor has been retrieved from :route:`docs/list`, use this to
//     paginate through all Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/list/continue extends Operation {
  id: docs/list/continue,
  path: "/paper/docs/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/list/continue.responses
}


// Operation: POST /paper/docs/users/list/continue
// Once a cursor has been retrieved from :route:`docs/users/list`, use this to
//     paginate through all users on the Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/users/list/continue extends Operation {
  id: docs/users/list/continue,
  path: "/paper/docs/users/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/users/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/users/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/users/list/continue.responses
}


// Operation: POST /team/groups/update
// Updates a group's name and/or external ID.
// 
//     Permission : Team member management.
one sig Operation_groups/update extends Operation {
  id: groups/update,
  path: "/team/groups/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/update_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/update.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/update.responses
}


// Operation: POST /sharing/unshare_file
// Remove all members from this file. Does not remove inherited members.
one sig Operation_unshare_file extends Operation {
  id: unshare_file,
  path: "/sharing/unshare_file",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_unshare_file_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unshare_file.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unshare_file.responses
}


// Operation: POST /file_requests/count
// Returns the total number of file requests owned by this user. Includes both open and
//     closed file requests.
one sig Operation_count extends Operation {
  id: count,
  path: "/file_requests/count",
  method: "POST",
  responses: set Response
}
fact Operation_count_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_count.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_count.responses
}


// Operation: POST /users/get_space_usage
// Get the space usage information for the current user's account.
one sig Operation_get_space_usage extends Operation {
  id: get_space_usage,
  path: "/users/get_space_usage",
  method: "POST",
  responses: set Response
}
fact Operation_get_space_usage_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_space_usage.responses
}


// Operation: POST /sharing/relinquish_file_membership
// The current user relinquishes their membership in the designated file.
//     Note that the current user may still have inherited access to this file
//     through the parent folder.
one sig Operation_relinquish_file_membership extends Operation {
  id: relinquish_file_membership,
  path: "/sharing/relinquish_file_membership",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_relinquish_file_membership_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_relinquish_file_membership.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_relinquish_file_membership.responses
}


// Operation: POST /files/properties/template/list
// Execute properties/template/list
one sig Operation_properties/template/list extends Operation {
  id: properties/template/list,
  path: "/files/properties/template/list",
  method: "POST",
  responses: set Response
}
fact Operation_properties/template/list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/list.responses
}


// Operation: POST /sharing/remove_file_member_2
// Removes a specified member from the file.
one sig Operation_remove_file_member_2 extends Operation {
  id: remove_file_member_2,
  path: "/sharing/remove_file_member_2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_remove_file_member_2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_remove_file_member_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_remove_file_member_2.responses
}


// Operation: POST /file_requests/get
// Returns the specified file request.
one sig Operation_get extends Operation {
  id: get,
  path: "/file_requests/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get.responses
}


// Operation: POST /file_properties/templates/list_for_user
// Get the template identifiers for a team. To get the schema of
//     each template use :route:`templates/get_for_user`. This endpoint can't be
//     called on a team member or admin's behalf.
one sig Operation_templates/list_for_user extends Operation {
  id: templates/list_for_user,
  path: "/file_properties/templates/list_for_user",
  method: "POST",
  responses: set Response
}
fact Operation_templates/list_for_user_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/list_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/list_for_user.responses
}


// Operation: POST /paper/folders/create
// Create a new Paper folder with the provided info.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_folders/create extends Operation {
  id: folders/create,
  path: "/paper/folders/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_folders/create_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_folders/create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_folders/create.responses
}


// Operation: POST /paper/docs/download
// Exports and downloads Paper doc either as HTML or markdown.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_docs/download extends Operation {
  id: docs/download,
  path: "/paper/docs/download",
  method: "POST",
  responses: set Response
}
fact Operation_docs/download_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/download.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/download.responses
}


// Operation: POST /sharing/unmount_folder
// The current user unmounts the designated folder. They can re-mount the
//     folder at a later time using :route:`mount_folder`.
one sig Operation_unmount_folder extends Operation {
  id: unmount_folder,
  path: "/sharing/unmount_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_unmount_folder_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unmount_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unmount_folder.responses
}


// Operation: POST /team/devices/revoke_device_session
// Revoke a device session of a team's member.
one sig Operation_devices/revoke_device_session extends Operation {
  id: devices/revoke_device_session,
  path: "/team/devices/revoke_device_session",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_devices/revoke_device_session_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices/revoke_device_session.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices/revoke_device_session.responses
}


// Operation: POST /team_log/get_events/continue
// Once a cursor has been retrieved from :route:`get_events`, use this to paginate through all events.
// 
//     Permission : Team Auditing.
one sig Operation_get_events/continue extends Operation {
  id: get_events/continue,
  path: "/team_log/get_events/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_events/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_events/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_events/continue.responses
}


// Operation: POST /team/members/get_info:2
// Returns information about multiple team members.
// 
//     Permission : Team information
// 
//     This endpoint will return :field:`MembersGetInfoItem.id_not_found`,
//     for IDs (or emails) that cannot be matched to a valid team member.
one sig Operation_members/get_info:2 extends Operation {
  id: members/get_info:2,
  path: "/team/members/get_info:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/get_info:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/get_info:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/get_info:2.responses
}


// Operation: POST /sharing/check_job_status
// Returns the status of an asynchronous job.
one sig Operation_check_job_status extends Operation {
  id: check_job_status,
  path: "/sharing/check_job_status",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_check_job_status_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_job_status.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_job_status.responses
}


// Operation: POST /team/legal_holds/list_held_revisions
// List the file metadata that's under the hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/list_held_revisions extends Operation {
  id: legal_holds/list_held_revisions,
  path: "/team/legal_holds/list_held_revisions",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/list_held_revisions_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/list_held_revisions.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/list_held_revisions.responses
}


// Operation: POST /sharing/list_folders
// Return the list of all shared folders the current user has access to.
one sig Operation_list_folders extends Operation {
  id: list_folders,
  path: "/sharing/list_folders",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folders_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folders.responses
}


// Operation: POST /team/sharing_allowlist/list
// Lists Approve List entries for given team, from newest to oldest, returning
//     up to `limit` entries at a time. If there are more than `limit` entries
//     associated with the current team, more can be fetched by passing the
//     returned `cursor` to :route:`sharing_allowlist/list/continue`.
one sig Operation_sharing_allowlist/list extends Operation {
  id: sharing_allowlist/list,
  path: "/team/sharing_allowlist/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_sharing_allowlist/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist/list.responses
}


// Operation: POST /paper/docs/users/list
// Lists all users who visited the Paper doc or users with explicit access. This call
//     excludes users who have been removed. The list is sorted by the date of the visit or
//     the share date.
// 
//     The list will include both users, the explicitly shared ones as well as those
//     who came in using the Paper url link.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/users/list extends Operation {
  id: docs/users/list,
  path: "/paper/docs/users/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/users/list_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/users/list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/users/list.responses
}


// Operation: POST /paper/docs/users/add
// Allows an owner or editor to add users to a Paper doc or change their permissions
//     using their email address or Dropbox account ID.
// 
//     The doc owner's permissions cannot be changed.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/users/add extends Operation {
  id: docs/users/add,
  path: "/paper/docs/users/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/users/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/users/add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/users/add.responses
}


// Operation: POST /files/paper/create
// 
//     Creates a new Paper doc with the provided content.
//      Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_paper/create extends Operation {
  id: paper/create,
  path: "/files/paper/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_paper/create_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_paper/create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_paper/create.responses
}


// Operation: POST /files/list_revisions
// Returns revisions for files based on a file path or a file id. The file path or file id is
//     identified from the latest file entry at the given file path or id. This end point allows your
//     app to query either by file path or file id by setting the mode parameter appropriately.
// 
//     In the :field:`ListRevisionsMode.path` (default) mode, all revisions at the same
//     file path as the latest file entry are
//     returned. If revisions with the same file id are desired, then mode must be set to
//     :field:`ListRevisionsMode.id`. The :field:`ListRevisionsMode.id` mode is useful to retrieve
//     revisions for a given file across moves or renames.
one sig Operation_list_revisions extends Operation {
  id: list_revisions,
  path: "/files/list_revisions",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_revisions_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_revisions.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_revisions.responses
}


// Operation: POST /team/groups/get_info
// Retrieves information about one or more groups. Note that the optional field
//      :field:`GroupFullInfo.members` is not returned for system-managed groups.
// 
//     Permission : Team Information.
one sig Operation_groups/get_info extends Operation {
  id: groups/get_info,
  path: "/team/groups/get_info",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/get_info_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/get_info.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/get_info.responses
}


// Operation: POST /team/sharing_allowlist/list/continue
// Lists entries associated with given team, starting from a the cursor. See :route:`sharing_allowlist/list`.
one sig Operation_sharing_allowlist/list/continue extends Operation {
  id: sharing_allowlist/list/continue,
  path: "/team/sharing_allowlist/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_sharing_allowlist/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist/list/continue.responses
}


// Operation: POST /sharing/get_file_metadata/batch
// Returns shared file metadata.
one sig Operation_get_file_metadata/batch extends Operation {
  id: get_file_metadata/batch,
  path: "/sharing/get_file_metadata/batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_file_metadata/batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_metadata/batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_metadata/batch.responses
}


// Operation: POST /file_properties/properties/add
// Add property groups to a Dropbox file. See :route:`templates/add_for_user` or
//     :route:`templates/add_for_team` to create new templates.
one sig Operation_properties/add extends Operation {
  id: properties/add,
  path: "/file_properties/properties/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/add.responses
}


// Operation: POST /team/namespaces/list/continue
// Once a cursor has been retrieved from :route:`namespaces/list`, use this to paginate
//     through all team-accessible namespaces. Duplicates may occur in the list.
one sig Operation_namespaces/list/continue extends Operation {
  id: namespaces/list/continue,
  path: "/team/namespaces/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_namespaces/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_namespaces/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_namespaces/list/continue.responses
}


// Operation: POST /files/search/continue:2
// Fetches the next page of search results returned from :route:`search:2`.
// 
//     Note: :route:`search:2` along with :route:`search/continue:2` can only be used to
//     retrieve a maximum of 10,000 matches.
// 
//     Recent changes may not immediately be reflected in search results due to a short delay in indexing.
//     Duplicate results may be returned across pages. Some results may not be returned.
one sig Operation_search/continue:2 extends Operation {
  id: search/continue:2,
  path: "/files/search/continue:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_search/continue:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_search/continue:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_search/continue:2.responses
}


// Operation: POST /team/get_info
// Retrieves information about a team.
one sig Operation_get_info extends Operation {
  id: get_info,
  path: "/team/get_info",
  method: "POST",
  responses: set Response
}
fact Operation_get_info_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_info.responses
}


// Operation: POST /file_properties/templates/get_for_user
// Get the schema for a specified template. This endpoint can't be called on a team member or admin's behalf.
one sig Operation_templates/get_for_user extends Operation {
  id: templates/get_for_user,
  path: "/file_properties/templates/get_for_user",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_templates/get_for_user_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates/get_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates/get_for_user.responses
}


// Operation: POST /contacts/delete_manual_contacts_batch
// Removes manually added contacts from the given list.
one sig Operation_delete_manual_contacts_batch extends Operation {
  id: delete_manual_contacts_batch,
  path: "/contacts/delete_manual_contacts_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_delete_manual_contacts_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_manual_contacts_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_manual_contacts_batch.responses
}


// Operation: POST /files/restore
// Restore a specific revision of a file to the given path.
one sig Operation_restore extends Operation {
  id: restore,
  path: "/files/restore",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_restore_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_restore.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_restore.responses
}


// Operation: POST /file_properties/properties/search
// Search across property templates for particular property field values.
one sig Operation_properties/search extends Operation {
  id: properties/search,
  path: "/file_properties/properties/search",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/search_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/search.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/search.responses
}


// Operation: POST /team/legal_holds/list_policies
// Lists legal holds on a team.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/list_policies extends Operation {
  id: legal_holds/list_policies,
  path: "/team/legal_holds/list_policies",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/list_policies_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/list_policies.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/list_policies.responses
}


// Operation: POST /files/create_folder_batch/check
// Returns the status of an asynchronous job for :route:`create_folder_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_create_folder_batch/check extends Operation {
  id: create_folder_batch/check,
  path: "/files/create_folder_batch/check",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_create_folder_batch/check_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder_batch/check.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_folder_batch/check.responses
}


// Operation: POST /team/members/delete_profile_photo:2
// Deletes a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members/delete_profile_photo:2 extends Operation {
  id: members/delete_profile_photo:2,
  path: "/team/members/delete_profile_photo:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/delete_profile_photo:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/delete_profile_photo:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/delete_profile_photo:2.responses
}


// Operation: POST /sharing/list_folder_members/continue
// Once a cursor has been retrieved from :route:`list_folder_members`, use this to paginate
//     through all shared folder members.
one sig Operation_list_folder_members/continue extends Operation {
  id: list_folder_members/continue,
  path: "/sharing/list_folder_members/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder_members/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_members/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_members/continue.responses
}


// Operation: POST /files/get_file_lock_batch
// 
//     Return the lock metadata for the given list of paths.
//     
one sig Operation_get_file_lock_batch extends Operation {
  id: get_file_lock_batch,
  path: "/files/get_file_lock_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_file_lock_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_lock_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_lock_batch.responses
}


// Operation: POST /files/paper/update
// 
//     Updates an existing Paper doc with the provided content.
//      Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_paper/update extends Operation {
  id: paper/update,
  path: "/files/paper/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_paper/update_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_paper/update.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_paper/update.responses
}


// Operation: POST /team/reports/get_storage
// Retrieves reporting data about a team's storage usage.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports/get_storage extends Operation {
  id: reports/get_storage,
  path: "/team/reports/get_storage",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_reports/get_storage_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports/get_storage.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports/get_storage.responses
}


// Operation: POST /team/members/suspend
// Suspend a member from a team.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members/suspend extends Operation {
  id: members/suspend,
  path: "/team/members/suspend",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/suspend_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/suspend.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/suspend.responses
}


// Operation: POST /files/move_batch:2
// Move multiple files or folders to different locations at once in the
//     user's Dropbox.
// 
//     This route will return job ID immediately and do the async moving job in
//     background. Please use :route:`move_batch/check:1` to check the job status.
one sig Operation_move_batch:2 extends Operation {
  id: move_batch:2,
  path: "/files/move_batch:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_move_batch:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move_batch:2.responses
}


// Operation: POST /paper/docs/archive
// Marks the given Paper doc as archived.
// 
//     This action can be performed or undone by anyone with edit permissions to the doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information.
one sig Operation_docs/archive extends Operation {
  id: docs/archive,
  path: "/paper/docs/archive",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/archive_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/archive.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/archive.responses
}


// Operation: POST /files/save_url
// Save the data from a specified URL into a file in user's Dropbox.
// 
//     Note that the transfer from the URL must complete within 15 minutes, or the
//     operation will time out and the job will fail.
// 
//     If the given path already exists, the file will be renamed to avoid the
//     conflict (e.g. myfile (1).txt).
one sig Operation_save_url extends Operation {
  id: save_url,
  path: "/files/save_url",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_save_url_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_save_url.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_save_url.responses
}


// Operation: POST /sharing/unshare_folder
// Allows a shared folder owner to unshare the folder.
// 
//     You'll need to call :route:`check_job_status` to determine if the action has
//     completed successfully.
one sig Operation_unshare_folder extends Operation {
  id: unshare_folder,
  path: "/sharing/unshare_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_unshare_folder_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unshare_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unshare_folder.responses
}


// Operation: POST /team/legal_holds/release_policy
// Releases a legal hold by Id.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds/release_policy extends Operation {
  id: legal_holds/release_policy,
  path: "/team/legal_holds/release_policy",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_legal_holds/release_policy_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds/release_policy.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds/release_policy.responses
}


// Operation: POST /file_properties/properties/update
// Add, update or remove properties associated with the supplied file and templates.
//     This endpoint should be used instead of :route:`properties/overwrite` when property groups
//     are being updated via a "delta" instead of via a "snapshot" . In other words, this endpoint
//     will not delete any omitted fields from a property group, whereas :route:`properties/overwrite`
//     will delete any fields that are omitted from a property group.
one sig Operation_properties/update extends Operation {
  id: properties/update,
  path: "/file_properties/properties/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/update_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/update.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/update.responses
}


// Operation: POST /files/tags/get
// Get list of tags assigned to items.
one sig Operation_tags/get extends Operation {
  id: tags/get,
  path: "/files/tags/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_tags/get_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags/get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags/get.responses
}


// Operation: POST /team/member_space_limits/set_custom_quota
// Set users custom quota. Custom quota has to be at least 15GB.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits/set_custom_quota extends Operation {
  id: member_space_limits/set_custom_quota,
  path: "/team/member_space_limits/set_custom_quota",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/set_custom_quota_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/set_custom_quota.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/set_custom_quota.responses
}


// Operation: POST /file_properties/properties/remove
// Permanently removes the specified property group from the file. To remove specific property field key
//     value pairs, see :route:`properties/update`.
//     To update a template, see
//     :route:`templates/update_for_user` or :route:`templates/update_for_team`.
//     To remove a template, see
//     :route:`templates/remove_for_user` or :route:`templates/remove_for_team`.
one sig Operation_properties/remove extends Operation {
  id: properties/remove,
  path: "/file_properties/properties/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/remove.responses
}


// Operation: POST /files/search:2
// Searches for files and folders.
// 
//     Note: :route:`search:2` along with :route:`search/continue:2` can only be used to
//     retrieve a maximum of 10,000 matches.
// 
//     Recent changes may not immediately be reflected in search results due to a short delay in indexing.
//     Duplicate results may be returned across pages. Some results may not be returned.
one sig Operation_search:2 extends Operation {
  id: search:2,
  path: "/files/search:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_search:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_search:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_search:2.responses
}


// Operation: POST /file_properties/properties/overwrite
// Overwrite property groups associated with a file. This endpoint should be used
//     instead of :route:`properties/update` when property groups are being updated via a
//     "snapshot" instead of via a "delta". In other words, this endpoint will delete all
//     omitted fields from a property group, whereas :route:`properties/update` will only
//     delete fields that are explicitly marked for deletion.
one sig Operation_properties/overwrite extends Operation {
  id: properties/overwrite,
  path: "/file_properties/properties/overwrite",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/overwrite_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/overwrite.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/overwrite.responses
}


// Operation: POST /sharing/update_folder_policy
// Update the sharing policies for a shared folder.
// 
//     User must have :field:`AccessLevel.owner` access to the shared folder to update its policies.
one sig Operation_update_folder_policy extends Operation {
  id: update_folder_policy,
  path: "/sharing/update_folder_policy",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_update_folder_policy_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_folder_policy.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_folder_policy.responses
}


// Operation: POST /team/groups/members/list
// Lists members of a group.
// 
//     Permission : Team Information.
one sig Operation_groups/members/list extends Operation {
  id: groups/members/list,
  path: "/team/groups/members/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/members/list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/members/list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/members/list.responses
}


// Operation: POST /team/member_space_limits/excluded_users/remove
// Remove users from member space limits excluded users list.
one sig Operation_member_space_limits/excluded_users/remove extends Operation {
  id: member_space_limits/excluded_users/remove,
  path: "/team/member_space_limits/excluded_users/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/excluded_users/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/excluded_users/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/excluded_users/remove.responses
}


// Operation: POST /files/permanently_delete
// Permanently delete the file or folder at a given path
//     (see https://www.dropbox.com/en/help/40).
// 
//     If the given file or folder is not yet deleted, this route will first delete it.
//     It is possible for this route to successfully delete, then fail to permanently
//     delete.
// 
//     Note: This endpoint is only available for Dropbox Business apps.
one sig Operation_permanently_delete extends Operation {
  id: permanently_delete,
  path: "/files/permanently_delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_permanently_delete_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_permanently_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_permanently_delete.responses
}


// Operation: POST /sharing/remove_folder_member
// Allows an owner or editor (if the ACL update policy allows) of a shared
//     folder to remove another member.
one sig Operation_remove_folder_member extends Operation {
  id: remove_folder_member,
  path: "/sharing/remove_folder_member",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_remove_folder_member_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_remove_folder_member.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_remove_folder_member.responses
}


// Operation: POST /sharing/relinquish_folder_membership
// The current user relinquishes their membership in the designated shared
//     folder and will no longer have access to the folder.  A folder owner cannot
//     relinquish membership in their own folder.
// 
//     This will run synchronously if leave_a_copy is false, and asynchronously
//     if leave_a_copy is true.
one sig Operation_relinquish_folder_membership extends Operation {
  id: relinquish_folder_membership,
  path: "/sharing/relinquish_folder_membership",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_relinquish_folder_membership_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_relinquish_folder_membership.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_relinquish_folder_membership.responses
}


// Operation: POST /team/groups/list
// Lists groups on a team.
// 
//     Permission : Team Information.
one sig Operation_groups/list extends Operation {
  id: groups/list,
  path: "/team/groups/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/list.responses
}


// Operation: POST /auth/token/from_oauth1
// Creates an OAuth 2.0 access token from the supplied OAuth 1.0 access token.
one sig Operation_token/from_oauth1 extends Operation {
  id: token/from_oauth1,
  path: "/auth/token/from_oauth1",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_token/from_oauth1_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token/from_oauth1.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_token/from_oauth1.responses
}


// Operation: POST /files/properties/update
// Execute properties/update
one sig Operation_properties/update extends Operation {
  id: properties/update,
  path: "/files/properties/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/update_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/update.responses
}


// Operation: POST /file_requests/list:2
// Returns a list of file requests owned by this user. For apps with the app
//     folder permission, this will only return file requests with destinations in
//     the app folder.
one sig Operation_list:2 extends Operation {
  id: list:2,
  path: "/file_requests/list:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list:2.responses
}


// Operation: POST /files/list_folder/longpoll
// A longpoll endpoint to wait for changes on an account. In conjunction with
//     :route:`list_folder/continue`, this call gives you a low-latency way to
//     monitor an account for file changes. The connection will block until there
//     are changes available or a timeout occurs. This endpoint is useful mostly
//     for client-side apps. If you're looking for server-side notifications,
//     check out our
//     :link:`webhooks documentation https://www.dropbox.com/developers/reference/webhooks`.
one sig Operation_list_folder/longpoll extends Operation {
  id: list_folder/longpoll,
  path: "/files/list_folder/longpoll",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder/longpoll_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder/longpoll.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder/longpoll.responses
}


// Operation: POST /team/members/set_profile:2
// Updates a team member's profile.
// 
//     Permission : Team member management.
one sig Operation_members/set_profile:2 extends Operation {
  id: members/set_profile:2,
  path: "/team/members/set_profile:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_profile:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_profile:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_profile:2.responses
}


// Operation: POST /sharing/check_remove_member_job_status
// Returns the status of an asynchronous job for sharing a folder.
one sig Operation_check_remove_member_job_status extends Operation {
  id: check_remove_member_job_status,
  path: "/sharing/check_remove_member_job_status",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_check_remove_member_job_status_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_remove_member_job_status.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_remove_member_job_status.responses
}


// Operation: POST /team/groups/members/set_access_type
// Sets a member's access type in a group.
// 
//     Permission : Team member management.
one sig Operation_groups/members/set_access_type extends Operation {
  id: groups/members/set_access_type,
  path: "/team/groups/members/set_access_type",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/members/set_access_type_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/members/set_access_type.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/members/set_access_type.responses
}


// Operation: POST /files/upload_session/finish
// Finish an upload session and save the uploaded data to the given file
//     path.
// 
//     A single request should not upload more than 150 MB. The maximum size of
//     a file one can upload to an upload session is 350 GB.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page https://www.dropbox.com/developers/reference/data-transport-limit`. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_upload_session/finish extends Operation {
  id: upload_session/finish,
  path: "/files/upload_session/finish",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/finish_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/finish.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session/finish.responses
}


// Operation: POST /team/groups/job_status/get
// Once an async_job_id is returned from :route:`groups/delete`,
//     :route:`groups/members/add` , or :route:`groups/members/remove`
//     use this method to poll the status of granting/revoking
//     group members' access to group-owned resources.
// 
//     Permission : Team member management.
one sig Operation_groups/job_status/get extends Operation {
  id: groups/job_status/get,
  path: "/team/groups/job_status/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/job_status/get_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/job_status/get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/job_status/get.responses
}


// Operation: POST /check/app
// This endpoint performs App Authentication, validating the supplied app key and secret,
//     and returns the supplied string, to allow you to test your code and connection to the
//     Dropbox API. It has no other effect. If you receive an HTTP 200 response with the supplied
//     query, it indicates at least part of the Dropbox API infrastructure is working and that the
//     app key and secret valid.
one sig Operation_app extends Operation {
  id: app,
  path: "/check/app",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_app_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_app.responses
}


// Operation: POST /team/linked_apps/list_members_linked_apps
// List all applications linked to the team members' accounts.
// 
//     Note, this endpoint doesn't list any team-linked applications.
one sig Operation_linked_apps/list_members_linked_apps extends Operation {
  id: linked_apps/list_members_linked_apps,
  path: "/team/linked_apps/list_members_linked_apps",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_linked_apps/list_members_linked_apps_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps/list_members_linked_apps.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps/list_members_linked_apps.responses
}


// Operation: POST /paper/docs/sharing_policy/get
// Gets the default sharing policy for the given Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/sharing_policy/get extends Operation {
  id: docs/sharing_policy/get,
  path: "/paper/docs/sharing_policy/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/sharing_policy/get_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/sharing_policy/get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/sharing_policy/get.responses
}


// Operation: POST /users/get_current_account
// Get information about the current user's account.
one sig Operation_get_current_account extends Operation {
  id: get_current_account,
  path: "/users/get_current_account",
  method: "POST",
  responses: set Response
}
fact Operation_get_current_account_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_current_account.responses
}


// Operation: POST /files/get_temporary_link
// Get a temporary link to stream content of a file. This link will expire in four hours and
//     afterwards you will get 410 Gone. This URL should not be used to display content directly
//     in the browser. The Content-Type of the link is determined automatically by the file's mime type.
one sig Operation_get_temporary_link extends Operation {
  id: get_temporary_link,
  path: "/files/get_temporary_link",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_temporary_link_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_temporary_link.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_temporary_link.responses
}


// Operation: POST /team/members/list
// Lists members of a team.
// 
//     Permission : Team information.
one sig Operation_members/list extends Operation {
  id: members/list,
  path: "/team/members/list",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/list_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/list.responses
}


// Operation: POST /files/delete_batch/check
// Returns the status of an asynchronous job for :route:`delete_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_delete_batch/check extends Operation {
  id: delete_batch/check,
  path: "/files/delete_batch/check",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_delete_batch/check_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_batch/check.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_batch/check.responses
}


// Operation: POST /paper/docs/users/remove
// Allows an owner or editor to remove users from a Paper doc using their email address or
//     Dropbox account ID.
// 
//     The doc owner cannot be removed.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/users/remove extends Operation {
  id: docs/users/remove,
  path: "/paper/docs/users/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/users/remove_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/users/remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/users/remove.responses
}


// Operation: POST /files/properties/overwrite
// Execute properties/overwrite
one sig Operation_properties/overwrite extends Operation {
  id: properties/overwrite,
  path: "/files/properties/overwrite",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/overwrite_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/overwrite.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/overwrite.responses
}


// Operation: POST /files/get_thumbnail:2
// Get a thumbnail for an image.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_thumbnail:2 extends Operation {
  id: get_thumbnail:2,
  path: "/files/get_thumbnail:2",
  method: "POST",
  responses: set Response
}
fact Operation_get_thumbnail:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail:2.responses
}


// Operation: POST /team/team_folder/create
// Creates a new, active, team folder with no members. This endpoint can only be used for teams
//     that do not already have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/create extends Operation {
  id: team_folder/create,
  path: "/team/team_folder/create",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/create_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/create.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/create.responses
}


// Operation: POST /files/properties/template/get
// Execute properties/template/get
one sig Operation_properties/template/get extends Operation {
  id: properties/template/get,
  path: "/files/properties/template/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_properties/template/get_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties/template/get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties/template/get.responses
}


// Operation: POST /team/members/secondary_emails/delete
// Delete secondary emails from users
// 
//     Permission : Team member management.
// 
//     Users will be notified of deletions of verified secondary emails at both the secondary email and their primary email.
one sig Operation_members/secondary_emails/delete extends Operation {
  id: members/secondary_emails/delete,
  path: "/team/members/secondary_emails/delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/secondary_emails/delete_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/secondary_emails/delete.responses
}


// Operation: POST /team/member_space_limits/excluded_users/add
// Add users to member space limits excluded users list.
one sig Operation_member_space_limits/excluded_users/add extends Operation {
  id: member_space_limits/excluded_users/add,
  path: "/team/member_space_limits/excluded_users/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/excluded_users/add_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/excluded_users/add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/excluded_users/add.responses
}


// Operation: POST /paper/docs/get_folder_info
// Retrieves folder information for the given Paper doc. This includes:
// 
//       - folder sharing policy; permissions for subfolders are set by the top-level folder.
// 
//       - full 'filepath', i.e. the list of folders (both folderId and folderName) from
//         the root folder to the folder directly containing the Paper doc.
// 
// 
//     If the Paper doc is not in any folder (aka unfiled) the response will be empty.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/get_folder_info extends Operation {
  id: docs/get_folder_info,
  path: "/paper/docs/get_folder_info",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/get_folder_info_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/get_folder_info.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/get_folder_info.responses
}


// Operation: POST /files/lock_file_batch
// 
//     Lock the files at the given paths. A locked file will be writable only by the lock holder.
//     A successful response indicates that the file has been locked. Returns a list of the
//     locked file paths and their metadata after this operation.
//     
one sig Operation_lock_file_batch extends Operation {
  id: lock_file_batch,
  path: "/files/lock_file_batch",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_lock_file_batch_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_lock_file_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_lock_file_batch.responses
}


// Operation: POST /sharing/update_file_member
// Changes a member's access on a shared file.
one sig Operation_update_file_member extends Operation {
  id: update_file_member,
  path: "/sharing/update_file_member",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_update_file_member_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_file_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_file_member.responses
}


// Operation: POST /team/team_folder/archive
// Sets an active team folder's status to archived and removes all folder and file members.
//     This endpoint cannot be used for teams that have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder/archive extends Operation {
  id: team_folder/archive,
  path: "/team/team_folder/archive",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_team_folder/archive_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder/archive.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder/archive.responses
}


// Operation: POST /files/copy_reference/get
// Get a copy reference to a file or folder. This reference string can be used to
//     save that file or folder to another user's Dropbox by passing it to
//     :route:`copy_reference/save`.
one sig Operation_copy_reference/get extends Operation {
  id: copy_reference/get,
  path: "/files/copy_reference/get",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_copy_reference/get_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_reference/get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_reference/get.responses
}


// Operation: POST /sharing/list_mountable_folders/continue
// Once a cursor has been retrieved from :route:`list_mountable_folders`, use this to paginate through all
//     mountable shared folders. The cursor must come from a previous call to :route:`list_mountable_folders` or
//     :route:`list_mountable_folders/continue`.
one sig Operation_list_mountable_folders/continue extends Operation {
  id: list_mountable_folders/continue,
  path: "/sharing/list_mountable_folders/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_mountable_folders/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_mountable_folders/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_mountable_folders/continue.responses
}


// Operation: POST /sharing/get_file_metadata
// Returns shared file metadata.
one sig Operation_get_file_metadata extends Operation {
  id: get_file_metadata,
  path: "/sharing/get_file_metadata",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_file_metadata_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_metadata.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_metadata.responses
}


// Operation: POST /files/copy_batch:2
// Copy multiple files or folders to different locations at once in the
//     user's Dropbox.
// 
//     This route will return job ID immediately and do the async copy job in
//     background. Please use :route:`copy_batch/check:1` to check the job status.
one sig Operation_copy_batch:2 extends Operation {
  id: copy_batch:2,
  path: "/files/copy_batch:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_copy_batch:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_batch:2.responses
}


// Operation: POST /team/devices/list_member_devices
// List all device sessions of a team's member.
one sig Operation_devices/list_member_devices extends Operation {
  id: devices/list_member_devices,
  path: "/team/devices/list_member_devices",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_devices/list_member_devices_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices/list_member_devices.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices/list_member_devices.responses
}


// Operation: POST /team/members/add
// Adds members to a team.
// 
//     Permission : Team member management
// 
//     A maximum of 20 members can be specified in a single call.
// 
//     If no Dropbox account exists with the email address specified, a new Dropbox account will
//     be created with the given email address, and that account will be invited to the team.
// 
//     If a personal Dropbox account exists with the email address specified in the call,
//     this call will create a placeholder Dropbox account for the user on the team and send an
//     email inviting the user to migrate their existing personal account onto the team.
// 
//     Team member management apps are required to set an initial given_name and surname for a
//     user to use in the team invitation and for 'Perform as team member' actions taken on
//     the user before they become 'active'.
one sig Operation_members/add extends Operation {
  id: members/add,
  path: "/team/members/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/add.responses
}


// Operation: POST /team/members/secondary_emails/add
// Add secondary emails to users.
// 
//     Permission : Team member management.
// 
//     Emails that are on verified domains will be verified automatically.
//     For each email address not on a verified domain a verification email will be sent.
one sig Operation_members/secondary_emails/add extends Operation {
  id: members/secondary_emails/add,
  path: "/team/members/secondary_emails/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/secondary_emails/add_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/secondary_emails/add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/secondary_emails/add.responses
}


// Operation: POST /sharing/modify_shared_link_settings
// Modify the shared link's settings.
// 
//     If the requested visibility conflict with the shared links policy of the team or the
//     shared folder (in case the linked file is part of a shared folder) then the
//     :field:`LinkPermissions.resolved_visibility` of the returned :type:`SharedLinkMetadata` will
//     reflect the actual visibility of the shared link and the
//     :field:`LinkPermissions.requested_visibility` will reflect the requested visibility.
one sig Operation_modify_shared_link_settings extends Operation {
  id: modify_shared_link_settings,
  path: "/sharing/modify_shared_link_settings",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_modify_shared_link_settings_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_modify_shared_link_settings.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_modify_shared_link_settings.responses
}


// Operation: POST /sharing/get_folder_metadata
// Returns shared folder metadata by its folder ID.
one sig Operation_get_folder_metadata extends Operation {
  id: get_folder_metadata,
  path: "/sharing/get_folder_metadata",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_get_folder_metadata_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_folder_metadata.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_folder_metadata.responses
}


// Operation: POST /sharing/get_shared_link_file
// Download the shared link's file from a user's Dropbox. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_shared_link_file extends Operation {
  id: get_shared_link_file,
  path: "/sharing/get_shared_link_file",
  method: "POST",
  responses: set Response
}
fact Operation_get_shared_link_file_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_shared_link_file.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_shared_link_file.responses
}


// Operation: POST /team/members/delete_profile_photo
// Deletes a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members/delete_profile_photo extends Operation {
  id: members/delete_profile_photo,
  path: "/team/members/delete_profile_photo",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/delete_profile_photo_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/delete_profile_photo.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/delete_profile_photo.responses
}


// Operation: POST /files/export
// Export a file from a user's Dropbox. This route only supports exporting files that cannot be downloaded directly
//      and whose :field:`ExportResult.file_metadata` has :field:`ExportInfo.export_as` populated. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_export extends Operation {
  id: export,
  path: "/files/export",
  method: "POST",
  responses: set Response
}
fact Operation_export_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_export.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_export.responses
}


// Operation: POST /files/upload_session/finish_batch/check
// Returns the status of an asynchronous job for :route:`upload_session/finish_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_upload_session/finish_batch/check extends Operation {
  id: upload_session/finish_batch/check,
  path: "/files/upload_session/finish_batch/check",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_upload_session/finish_batch/check_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session/finish_batch/check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session/finish_batch/check.responses
}


// Operation: POST /files/copy_batch/check:2
// Returns the status of an asynchronous job for :route:`copy_batch:1`. If
//     success, it returns list of results for each entry.
one sig Operation_copy_batch/check:2 extends Operation {
  id: copy_batch/check:2,
  path: "/files/copy_batch/check:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_copy_batch/check:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_batch/check:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_batch/check:2.responses
}


// Operation: POST /team/members/list:2
// Lists members of a team.
// 
//     Permission : Team information.
one sig Operation_members/list:2 extends Operation {
  id: members/list:2,
  path: "/team/members/list:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/list:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/list:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/list:2.responses
}


// Operation: POST /team/members/remove
// Removes a member from a team.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
// 
//     Accounts can be recovered via :route:`members/recover` for a 7 day period
//     or until the account has been permanently deleted or transferred to another account
//     (whichever comes first). Calling :route:`members/add` while a user is still recoverable
//     on your team will return with :field:`MemberAddResult.user_already_on_team`.
// 
//     Accounts can have their files transferred via the admin console for a limited time, based on the version history
//     length associated with the team (180 days for most teams).
// 
//     This endpoint may initiate an asynchronous job. To obtain the final result
//     of the job, the client should periodically poll :route:`members/remove/job_status/get`.
one sig Operation_members/remove extends Operation {
  id: members/remove,
  path: "/team/members/remove",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/remove_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/remove.responses
}


// Operation: POST /sharing/transfer_folder
// Transfer ownership of a shared folder to a member of the shared folder.
// 
//     User must have :field:`AccessLevel.owner` access to the shared folder to perform a transfer.
one sig Operation_transfer_folder extends Operation {
  id: transfer_folder,
  path: "/sharing/transfer_folder",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_transfer_folder_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_transfer_folder.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_transfer_folder.responses
}


// Operation: POST /team/members/add:2
// Adds members to a team.
// 
//     Permission : Team member management
// 
//     A maximum of 20 members can be specified in a single call.
// 
//     If no Dropbox account exists with the email address specified, a new Dropbox account will
//     be created with the given email address, and that account will be invited to the team.
// 
//     If a personal Dropbox account exists with the email address specified in the call,
//     this call will create a placeholder Dropbox account for the user on the team and send an
//     email inviting the user to migrate their existing personal account onto the team.
// 
//     Team member management apps are required to set an initial given_name and surname for a
//     user to use in the team invitation and for 'Perform as team member' actions taken on
//     the user before they become 'active'.
one sig Operation_members/add:2 extends Operation {
  id: members/add:2,
  path: "/team/members/add:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/add:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/add:2.responses
}


// Operation: POST /sharing/list_file_members/continue
// Once a cursor has been retrieved from :route:`list_file_members` or
//     :route:`list_file_members/batch`, use this to paginate through all shared
//     file members.
one sig Operation_list_file_members/continue extends Operation {
  id: list_file_members/continue,
  path: "/sharing/list_file_members/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_file_members/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members/continue.responses
}


// Operation: POST /team/members/add/job_status/get:2
// Once an async_job_id is returned from :route:`members/add:2` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members/add/job_status/get:2 extends Operation {
  id: members/add/job_status/get:2,
  path: "/team/members/add/job_status/get:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/add/job_status/get:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/add/job_status/get:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/add/job_status/get:2.responses
}


// Operation: POST /check/user
// This endpoint performs User Authentication, validating the supplied access token,
//     and returns the supplied string, to allow you to test your code and connection to the
//     Dropbox API. It has no other effect. If you receive an HTTP 200 response with the supplied
//     query, it indicates at least part of the Dropbox API infrastructure is working and that the
//     access token is valid.
one sig Operation_user extends Operation {
  id: user,
  path: "/check/user",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_user_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_user.responses
}


// Operation: POST /contacts/delete_manual_contacts
// Removes all manually added contacts.
//     You'll still keep contacts who are on your team or who you imported.
//     New contacts will be added when you share.
one sig Operation_delete_manual_contacts extends Operation {
  id: delete_manual_contacts,
  path: "/contacts/delete_manual_contacts",
  method: "POST",
  responses: set Response
}
fact Operation_delete_manual_contacts_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_manual_contacts.responses
}


// Operation: POST /files/copy_reference/save
// Save a copy reference returned by :route:`copy_reference/get` to the user's Dropbox.
one sig Operation_copy_reference/save extends Operation {
  id: copy_reference/save,
  path: "/files/copy_reference/save",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_copy_reference/save_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_reference/save.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_reference/save.responses
}


// Operation: POST /team/members/list/continue
// Once a cursor has been retrieved from :route:`members/list`, use this to paginate
//     through all team members.
// 
//     Permission : Team information.
one sig Operation_members/list/continue extends Operation {
  id: members/list/continue,
  path: "/team/members/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/list/continue.responses
}


// Operation: POST /paper/docs/update
// Updates an existing Paper doc with the provided content.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_docs/update extends Operation {
  id: docs/update,
  path: "/paper/docs/update",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/update_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/update.responses
}


// Operation: POST /sharing/check_share_job_status
// Returns the status of an asynchronous job for sharing a folder.
one sig Operation_check_share_job_status extends Operation {
  id: check_share_job_status,
  path: "/sharing/check_share_job_status",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_check_share_job_status_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_share_job_status.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_share_job_status.responses
}


// Operation: POST /file_requests/list/continue
// Once a cursor has been retrieved from :route:`list:2`, use this to paginate through all
//     file requests. The cursor must come from a previous call to :route:`list:2` or
//     :route:`list/continue`.
one sig Operation_list/continue extends Operation {
  id: list/continue,
  path: "/file_requests/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list/continue_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list/continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list/continue.responses
}


// Operation: POST /sharing/set_access_inheritance
// Change the inheritance policy of an existing Shared Folder. Only permitted for shared folders in a shared team root.
// 
//     If a :field:`ShareFolderLaunch.async_job_id` is returned, you'll need to
//     call :route:`check_share_job_status` until the action completes to get the
//     metadata for the folder.
one sig Operation_set_access_inheritance extends Operation {
  id: set_access_inheritance,
  path: "/sharing/set_access_inheritance",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_set_access_inheritance_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_set_access_inheritance.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_set_access_inheritance.responses
}


// Operation: POST /team/groups/delete
// Deletes a group.
// 
//     The group is deleted immediately. However the revoking of group-owned resources
//     may take additional time.
//     Use the :route:`groups/job_status/get` to determine whether this process has completed.
// 
//     Permission : Team member management.
one sig Operation_groups/delete extends Operation {
  id: groups/delete,
  path: "/team/groups/delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/delete_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/delete.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/delete.responses
}


// Operation: POST /users/features/get_values
// Get a list of feature values that may be configured for the current account.
one sig Operation_features/get_values extends Operation {
  id: features/get_values,
  path: "/users/features/get_values",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_features/get_values_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_features/get_values.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_features/get_values.responses
}


// Operation: POST /paper/docs/folder_users/list/continue
// Once a cursor has been retrieved from :route:`docs/folder_users/list`, use this to
//     paginate through all users on the Paper folder.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs/folder_users/list/continue extends Operation {
  id: docs/folder_users/list/continue,
  path: "/paper/docs/folder_users/list/continue",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_docs/folder_users/list/continue_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs/folder_users/list/continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs/folder_users/list/continue.responses
}


// Operation: POST /team/member_space_limits/remove_custom_quota
// Remove users custom quota.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits/remove_custom_quota extends Operation {
  id: member_space_limits/remove_custom_quota,
  path: "/team/member_space_limits/remove_custom_quota",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_member_space_limits/remove_custom_quota_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits/remove_custom_quota.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits/remove_custom_quota.responses
}


// Operation: POST /team/groups/members/add
// Adds members to a group.
// 
//     The members are added immediately. However the granting of group-owned resources
//     may take additional time.
//     Use the :route:`groups/job_status/get` to determine whether this process has completed.
// 
//     Permission : Team member management.
one sig Operation_groups/members/add extends Operation {
  id: groups/members/add,
  path: "/team/groups/members/add",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_groups/members/add_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups/members/add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups/members/add.responses
}


// Operation: POST /files/move:2
// Move a file or folder to a different location in the user's Dropbox.
// 
//     If the source path is a folder all its contents will be moved.
one sig Operation_move:2 extends Operation {
  id: move:2,
  path: "/files/move:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_move:2_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move:2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_move:2.responses
}


// Operation: POST /files/list_folder/get_latest_cursor
// A way to quickly get a cursor for the folder's state. Unlike :route:`list_folder`,
//     :route:`list_folder/get_latest_cursor` doesn't return any entries. This endpoint is for app
//     which only needs to know about new files and modifications and doesn't need to know about
//     files that already exist in Dropbox.
one sig Operation_list_folder/get_latest_cursor extends Operation {
  id: list_folder/get_latest_cursor,
  path: "/files/list_folder/get_latest_cursor",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_list_folder/get_latest_cursor_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder/get_latest_cursor.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder/get_latest_cursor.responses
}


// Operation: POST /team/members/set_profile_photo:2
// Updates a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members/set_profile_photo:2 extends Operation {
  id: members/set_profile_photo:2,
  path: "/team/members/set_profile_photo:2",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/set_profile_photo:2_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/set_profile_photo:2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/set_profile_photo:2.responses
}


// Operation: POST /team/members/unsuspend
// Unsuspend a member from a team.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members/unsuspend extends Operation {
  id: members/unsuspend,
  path: "/team/members/unsuspend",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_members/unsuspend_Constraints {
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members/unsuspend.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members/unsuspend.responses
}


// Operation: POST /file_requests/delete
// Delete a batch of closed file requests.
one sig Operation_delete extends Operation {
  id: delete,
  path: "/file_requests/delete",
  method: "POST",
  request: Request,
  responses: set Response
}
fact Operation_delete_Constraints {
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete.responses
}


// Global constraints
fact APIConstraints {
  // All operations must have unique IDs
  all disj op1, op2: Operation | op1.id != op2.id
}

// Sample assertions for API verification
assert NoEmptyResponses {
  all op: Operation | some op.responses
}

// Run commands for analysis
pred show {}
run show for 3
check NoEmptyResponses for 4
