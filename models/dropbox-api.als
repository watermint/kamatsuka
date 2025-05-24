module api

// Generated from OpenAPI spec: Dropbox API
// Title: Dropbox API
// Version: 2.0

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

// Schema definitions
sig DeleteBatchResultData {
  metadata: Metadata,
}


sig MinimalFileLinkMetadata {
  id: lone Id,
  url: String,
  rev: Rev,
  path: lone String,
}


sig SearchV2Arg {
  include_highlights: lone Bool,
  match_field_options: lone SearchMatchFieldOptions,
  options: lone SearchOptions,
  query: String,
}


sig PaperDocDownloadDetails {
  event_uuid: String,
  export_file_format: PaperDownloadFormat,
}


sig ListRevisionsMode {
  tag: String,
}


sig TeamFolderArchiveArg {
  // Generic object with no specific type
}


sig DomainInvitesRequestToJoinTeamType {
  description: String,
}


sig GovernancePolicyZipPartDownloadedDetails {
  export_name: String,
  governance_policy_id: String,
  part: lone String,
  name: String,
  policy_type: lone PolicyType,
}


sig SsoAddLoginUrlType {
  description: String,
}


sig PendingUploadMode {
  tag: String,
}


sig TeamEventList {
  items: set TeamEvent
}


sig FilePermanentlyDeleteType {
  description: String,
}


sig TeamFolderChangeStatusType {
  description: String,
}


sig ListTeamDevicesResult {
  has_more: Bool,
  cursor: lone String,
  devices: set MemberDevices,
}


sig SuggestMembersPolicy {
  tag: String,
}


sig TwoStepVerificationPolicy {
  tag: String,
}


sig PreviewError {
  tag: String,
}


sig ResellerSupportPolicy {
  tag: String,
}


sig SpaceLimitsStatus {
  tag: String,
}


sig FileSharingInfo {
  // Generic object with no specific type
}


sig SharedContentAddLinkPasswordDetails {
}


sig TeamMergeRequestAcceptedShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_by: String,
}


sig LegalHoldsExportCancelledType {
  description: String,
}


sig DisabledDomainInvitesType {
  description: String,
}


sig ContentAdministrationPolicyChangedType {
  description: String,
}


sig LegalHoldsGetPolicyError {
  tag: String,
}


sig MemberPolicy {
  tag: String,
}


sig SharingInfo {
  read_only: Bool,
}


sig Rev {
  // Generic object with no specific type
}


sig TeamNamespacesListResult {
  has_more: Bool,
  namespaces: set NamespaceMetadata,
  cursor: String,
}


sig NoteAclTeamLinkDetails {
}


sig ReplayFileSharedLinkCreatedDetails {
}


sig RewindPolicy {
  tag: String,
}


sig ListFileMembersContinueArg {
  cursor: String,
}


sig SharedFolderChangeLinkPolicyType {
  description: String,
}


sig DeleteBatchJobStatus {
  tag: String,
}


sig PaperExternalViewForbidType {
  description: String,
}


sig SharedLinkAccessLevel {
  tag: String,
}


sig GroupMemberSelectorError {
  tag: String,
}


sig ListFileMembersArg {
  file: PathOrId,
  include_inherited: Bool,
  actions: set MemberAction,
  limit: Int,
}


sig PaperDocSharingPolicy {
  // Generic object with no specific type
}


sig PaperEnabledPolicy {
  tag: String,
}


sig DropboxPasswordsExportedType {
  description: String,
}


sig SharingChangeFolderJoinPolicyType {
  description: String,
}


sig PaperDocMentionDetails {
  event_uuid: String,
}


sig FolderPermission {
  reason: lone PermissionDeniedReason,
  action: FolderAction,
  allow: Bool,
}


sig NetworkControlChangePolicyType {
  description: String,
}


sig FileErrorResult {
  tag: String,
}


sig NoPasswordLinkViewReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig EmailIngestPolicyChangedType {
  description: String,
}


sig WebSessionLogInfo {
  // Generic object with no specific type
}


sig GetFileMetadataError {
  tag: String,
}


sig MemberRemoveExternalIdDetails {
  previous_value: MemberExternalId,
}


sig UserInfoArgs {
}


sig ShowcaseEnabledPolicy {
  tag: String,
}


sig ListFoldersArgs {
  actions: set FolderAction,
  limit: Int,
}


sig CaptureTranscriptPolicy {
  tag: String,
}


sig MemberSpaceLimitsRemoveExceptionDetails {
}


sig ApplyNamingConventionType {
  description: String,
}


sig PasswordStrengthRequirementsChangePolicyType {
  description: String,
}


sig GetFileMetadataBatchArg {
  files: set PathOrId,
  actions: set FileAction,
}


sig AccountId {
  // Primitive type: string
  value: String
}


sig SharedLinkSettingsAddExpirationDetails {
  shared_content_link: lone String,
  new_value: lone DropboxTimestamp,
  shared_content_access_level: AccessLevel,
}


sig TeamMergeRequestRejectedShownToPrimaryTeamType {
  description: String,
}


sig PrimaryTeamRequestCanceledDetails {
  secondary_team: String,
  sent_by: String,
}


sig PlacementRestriction {
  tag: String,
}


sig TeamMergeRequestExpiredShownToPrimaryTeamType {
  description: String,
}


sig GroupLogInfo {
  group_id: lone GroupId,
  display_name: String,
  external_id: lone GroupExternalId,
}


sig BinderRemoveSectionDetails {
  event_uuid: String,
  doc_title: String,
  binder_item_name: String,
}


sig ShowcaseFileRemovedType {
  description: String,
}


sig WriteConflictError {
  tag: String,
}


sig ExternalDriveBackupStatusChangedType {
  description: String,
}


sig SessionLogInfo {
  session_id: lone SessionId,
}


sig TeamMergeRequestReminderExtraDetails {
  tag: String,
}


sig MemberAddV2Result {
  tag: String,
}


sig FileGetCopyReferenceDetails {
}


sig SharedContentLinkMetadataBase {
  expiry: lone DropboxTimestamp,
  audience_options: set LinkAudience,
  link_permissions: set LinkPermission,
  current_audience: LinkAudience,
  audience_restricting_shared_folder: lone AudienceRestrictingSharedFolder,
  password_protected: Bool,
  access_level: lone AccessLevel,
}


sig DesktopClientSession {
  // Generic object with no specific type
}


sig ChangedEnterpriseConnectedTeamStatusDetails {
  previous_value: TrustedTeamsRequestState,
  action: FedHandshakeAction,
  additional_info: FederationStatusChangeAdditionalInfo,
  new_value: TrustedTeamsRequestState,
}


sig OrganizationName {
  organization: String,
}


sig TeamMemberStatus {
  tag: String,
}


sig TeamMergeRequestReminderShownToPrimaryTeamDetails {
  sent_to: String,
  secondary_team: String,
}


sig ListFolderMembersContinueArg {
  cursor: String,
}


sig UserOnPaperDocFilter {
  tag: String,
}


sig TeamEncryptionKeyRotateKeyDetails {
}


sig VisibilityPolicy {
  resolved_policy: AlphaResolvedVisibility,
  disallowed_reason: lone VisibilityPolicyDisallowedReason,
  policy: RequestedVisibility,
  allowed: Bool,
}


sig ReplayProjectTeamDeleteType {
  description: String,
}


sig SsoRemoveLogoutUrlType {
  description: String,
}


sig ExportInfo {
  export_options: set String,
  export_as: lone String,
}


sig PaperAccessType {
  tag: String,
}


sig PasswordResetAllType {
  description: String,
}


sig MemberChangeEmailDetails {
  new_value: EmailAddress,
  previous_value: lone EmailAddress,
}


sig MemberSpaceLimitsChangePolicyType {
  description: String,
}


sig GovernancePolicyAddFoldersType {
  description: String,
}


sig ThumbnailFormat {
  tag: String,
}


sig GroupMembersChangeResult {
  async_job_id: AsyncJobId,
  group_info: GroupFullInfo,
}


sig TokenGetAuthenticatedAdminError {
  tag: String,
}


sig ListRevisionsError {
  tag: String,
}


sig ClassificationCreateReportType {
  description: String,
}


sig ModifyTemplateError {
  tag: String,
}


sig GetCopyReferenceError {
  tag: String,
}


sig GovernancePolicyContentDisposedDetails {
  disposition_type: DispositionActionType,
  governance_policy_id: String,
  name: String,
  policy_type: lone PolicyType,
}


sig RevokeLinkedAppError {
  tag: String,
}


sig SharedLinkRemoveExpiryDetails {
  previous_value: lone DropboxTimestamp,
}


sig SharingChangeLinkEnforcePasswordPolicyType {
  description: String,
}


sig EventTypeArg {
  tag: String,
}


sig MembersSendWelcomeError {
  tag: String,
}


sig EmmRefreshAuthTokenType {
  description: String,
}


sig NoExpirationLinkGenReportFailedType {
  description: String,
}


sig TeamFolderArchiveJobStatus {
  tag: String,
}


sig TeamEncryptionKeyEnableKeyDetails {
}


sig DataPlacementRestrictionChangePolicyDetails {
  previous_value: PlacementRestriction,
  new_value: PlacementRestriction,
}


sig DropboxId {
  // Primitive type: string
  value: String
}


sig MemberSendInvitePolicy {
  tag: String,
}


sig TemplateOwnerType {
  tag: String,
}


sig AddFileMemberArgs {
  add_message_as_comment: Bool,
  members: set MemberSelector,
  file: PathOrId,
  custom_message: lone String,
  quiet: Bool,
  access_level: AccessLevel,
}


sig SharedLinkSettings {
  allow_download: lone Bool,
  link_password: lone String,
  require_password: lone Bool,
  expires: lone DropboxTimestamp,
  audience: lone LinkAudience,
  access: lone RequestedLinkAccessLevel,
  requested_visibility: lone RequestedVisibility,
}


sig VideoMetadata {
  // Generic object with no specific type
}


sig GroupSelectorError {
  tag: String,
}


sig TeamFolderStatus {
  tag: String,
}


sig MemberChangeEmailType {
  description: String,
}


sig CustomQuotaError {
  tag: String,
}


sig TeamMergeRequestSentShownToSecondaryTeamDetails {
  sent_to: String,
}


sig LaunchResultBase {
  tag: String,
}


sig AppLinkTeamType {
  description: String,
}


sig WebSessionsChangeIdleLengthPolicyDetails {
  new_value: lone WebSessionsIdleLengthPolicy,
  previous_value: lone WebSessionsIdleLengthPolicy,
}


sig LinkPermission {
  action: LinkAction,
  allow: Bool,
  reason: lone PermissionDeniedReason,
}


sig PrimaryTeamRequestReminderDetails {
  secondary_team: String,
  sent_to: String,
}


sig TeamMergeRequestCanceledShownToPrimaryTeamDetails {
  sent_by: String,
  secondary_team: String,
}


sig SharedContentRestoreMemberType {
  description: String,
}


sig GetCopyReferenceResult {
  expires: DropboxTimestamp,
  metadata: Metadata,
  copy_reference: String,
}


sig GroupsGetInfoResult {
  items: set GroupsGetInfoItem
}


sig RemoveFileMemberArg {
  file: PathOrId,
  member: MemberSelector,
}


sig MembersAddJobStatusV2Result {
  tag: String,
}


sig RewindPolicyChangedDetails {
  new_value: RewindPolicy,
  previous_value: RewindPolicy,
}


sig UploadSessionStartArg {
  content_hash: lone Sha256HexHash,
  close: Bool,
  session_type: lone UploadSessionType,
}


sig ExportMembersReportFailType {
  description: String,
}


sig DeviceUnlinkDetails {
  delete_data: Bool,
  session_info: lone SessionLogInfo,
  display_name: lone String,
}


sig CreateTeamInviteLinkDetails {
  expiry_date: String,
  link_url: String,
}


sig AccountCaptureNotificationType {
  tag: String,
}


sig GroupMemberSelector {
  group: GroupSelector,
  user: UserSelectorArg,
}


sig LegalHoldsChangeHoldDetailsType {
  description: String,
}


sig MemberSelectorError {
  tag: String,
}


sig ContentAdministrationPolicyChangedDetails {
  previous_value: String,
  new_value: String,
}


sig SharingChangeLinkAllowChangeExpirationPolicyDetails {
  previous_value: lone EnforceLinkPasswordPolicy,
  new_value: EnforceLinkPasswordPolicy,
}


sig SharedContentViewType {
  description: String,
}


sig MembersListV2Result {
  cursor: String,
  has_more: Bool,
  members: set TeamMemberInfoV2,
}


sig SharedContentRemoveMemberDetails {
  shared_content_access_level: lone AccessLevel,
}


sig RelocationBatchLaunch {
  tag: String,
}


sig SharingChangeFolderJoinPolicyDetails {
  previous_value: lone SharingFolderJoinPolicy,
  new_value: SharingFolderJoinPolicy,
}


sig TeamProfileAddLogoType {
  description: String,
}


sig SharedLinkAddExpiryDetails {
  new_value: DropboxTimestamp,
}


sig OrganizeFolderWithTidyType {
  description: String,
}


sig ChangedEnterpriseConnectedTeamStatusType {
  description: String,
}


sig GroupsListArg {
  limit: Int,
}


sig SharedLinkSettingsAllowDownloadEnabledType {
  description: String,
}


sig UnshareFileArg {
  file: PathOrId,
}


sig CameraUploadsPolicy {
  tag: String,
}


sig SfAddGroupDetails {
  target_asset_index: Int,
  team_name: String,
  original_folder_name: String,
  sharing_permission: lone String,
}


sig TeamMergeRequestRejectedShownToPrimaryTeamDetails {
  sent_by: String,
  secondary_team: String,
}


sig RemoveTagArg {
  path: Path,
  tag_text: TagText,
}


sig PaperContentPermanentlyDeleteType {
  description: String,
}


sig PaperChangeMemberLinkPolicyDetails {
  new_value: PaperMemberPolicy,
}


sig ExcludedUsersListResult {
  users: set MemberProfile,
  has_more: Bool,
  cursor: lone String,
}


sig LegalHoldsExportRemovedType {
  description: String,
}


sig PaperDocExport {
  // Generic object with no specific type
}


sig TokenGetAuthenticatedAdminResult {
  admin_profile: TeamMemberProfile,
}


sig ListFileMembersContinueError {
  tag: String,
}


sig RelocationBatchV2JobStatus {
  tag: String,
}


sig UploadSessionAppendArg {
  content_hash: lone Sha256HexHash,
  close: Bool,
  cursor: UploadSessionCursor,
}


sig NoteAclInviteOnlyDetails {
}


sig ShowcaseCreatedDetails {
  event_uuid: String,
}


sig LogoutType {
  description: String,
}


sig SharedContentRemoveInviteesDetails {
  invitees: set EmailAddress,
}


sig BackupAdminInvitationSentType {
  description: String,
}


sig DisplayNameLegacy {
  // Primitive type: string
  value: String
}


sig ClassificationChangePolicyType {
  description: String,
}


sig LegalHoldsExportDownloadedType {
  description: String,
}


sig FeaturesGetValuesBatchResult {
  values: set FeatureValue,
}


sig PropertiesSearchContinueArg {
  cursor: PropertiesSearchCursor,
}


sig SharedContentRemoveLinkPasswordType {
  description: String,
}


sig DeleteResult {
  // Generic object with no specific type
}


sig BackupStatus {
  tag: String,
}


sig AdminAlertSeverityEnum {
  tag: String,
}


sig WebSessionsIdleLengthPolicy {
  tag: String,
}


sig SharedLinkShareDetails {
  shared_link_owner: lone UserLogInfo,
  external_users: set ExternalUserLogInfo,
}


sig GroupSelector {
  tag: String,
}


sig DomainVerificationRemoveDomainDetails {
  domain_names: set String,
}


sig FilePermanentlyDeleteDetails {
}


sig TeamEncryptionKeyDisableKeyType {
  description: String,
}


sig SsoAddLogoutUrlDetails {
  new_value: lone String,
}


sig OpenNoteSharedType {
  description: String,
}


sig PermanentDeleteChangePolicyType {
  description: String,
}


sig PollError {
  tag: String,
}


sig FolderLinkRestrictionPolicyChangedDetails {
  previous_value: FolderLinkRestrictionPolicy,
  new_value: FolderLinkRestrictionPolicy,
}


sig MembersDeactivateBaseArg {
  user: UserSelectorArg,
}


sig CopyBatchArg {
  // Generic object with no specific type
}


sig GpsCoordinates {
  latitude: Int,
  longitude: Int,
}


sig BinderRenamePageDetails {
  previous_binder_item_name: lone String,
  doc_title: String,
  binder_item_name: String,
  event_uuid: String,
}


sig NoPasswordLinkGenReportFailedType {
  description: String,
}


sig ComputerBackupPolicyState {
  tag: String,
}


sig MembersSetPermissionsArg {
  new_role: AdminTier,
  user: UserSelectorArg,
}


sig DeleteSecondaryEmailResult {
  tag: String,
}


sig AllowDownloadDisabledDetails {
}


sig GroupExternalId {
  // Primitive type: string
  value: String
}


sig PaperDocRequestAccessDetails {
  event_uuid: String,
}


sig TeamProfileRemoveLogoDetails {
}


sig AddPropertiesError {
  tag: String,
}


sig AdminRole {
  tag: String,
}


sig EmmCreateUsageReportDetails {
}


sig ShowcaseUntrashedDeprecatedDetails {
  event_uuid: String,
}


sig TeamMemberRoleId {
  // Primitive type: string
  value: String
}


sig SharingChangeLinkPolicyDetails {
  new_value: SharingLinkPolicy,
  previous_value: lone SharingLinkPolicy,
}


sig ListFileMembersBatchArg {
  files: set PathOrId,
  limit: Int,
}


sig UserMembershipInfo {
  // Generic object with no specific type
}


sig ShowcaseTrashedType {
  description: String,
}


sig RevokeDeviceSessionBatchResult {
  revoke_devices_status: set RevokeDeviceSessionStatus,
}


sig EnabledDomainInvitesDetails {
}


sig FileChangeCommentSubscriptionDetails {
  new_value: FileCommentNotificationPolicy,
  previous_value: lone FileCommentNotificationPolicy,
}


sig AppLinkUserType {
  description: String,
}


sig LegalHoldsActivateAHoldDetails {
  name: String,
  end_date: lone DropboxTimestamp,
  legal_hold_id: String,
  start_date: DropboxTimestamp,
}


sig IntegrationConnectedDetails {
  integration_name: String,
}


sig PaperContentAddMemberDetails {
  event_uuid: String,
}


sig StartedEnterpriseAdminSessionType {
  description: String,
}


sig RelocationBatchResultData {
  metadata: Metadata,
}


sig PaperDocExportResult {
  title: String,
  mime_type: String,
  owner: String,
  revision: Int,
}


sig Date {
  // Primitive type: string
  value: String
}


sig GetSharedLinkMetadataArg {
  url: String,
  link_password: lone String,
  path: lone Path,
}


sig RelinquishFileMembershipError {
  tag: String,
}


sig PaperDocRevertDetails {
  event_uuid: String,
}


sig GroupsMembersListArg {
  limit: Int,
  group: GroupSelector,
}


sig ApiSessionLogInfo {
  request_id: RequestId,
}


sig GovernancePolicyRemoveFoldersDetails {
  reason: lone String,
  folders: set String,
  name: String,
  governance_policy_id: String,
  policy_type: lone PolicyType,
}


sig SmartSyncChangePolicyDetails {
  previous_value: lone SmartSyncPolicy,
  new_value: lone SmartSyncPolicy,
}


sig DeviceApprovalsAddExceptionDetails {
}


sig FileOrFolderLogInfo {
  path: PathLogInfo,
  file_size: lone Int,
  display_name: lone String,
  file_id: lone String,
}


sig SsoErrorType {
  description: String,
}


sig SharedContentChangeInviteeRoleType {
  description: String,
}


sig ShowcaseEditCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig TeamFolderArchiveError {
  tag: String,
}


sig TeamFolderListError {
  access_error: TeamFolderAccessError,
}


sig ShowcaseRequestAccessType {
  description: String,
}


sig AccountLockOrUnlockedDetails {
  previous_value: AccountState,
  new_value: AccountState,
}


sig SharingLinkPolicy {
  tag: String,
}


sig MembersUnsuspendError {
  tag: String,
}


sig SharedFolderMountDetails {
}


sig UploadSessionStartResult {
  session_id: String,
}


sig LegalHoldsPolicyReleaseArg {
  id: LegalHoldId,
}


sig PhotoSourceArg {
  tag: String,
}


sig DataResidencyMigrationRequestSuccessfulDetails {
}


sig LoginFailType {
  description: String,
}


sig ExportMetadata {
  name: String,
  size: Int,
  export_hash: lone Sha256HexHash,
  paper_revision: lone Int,
}


sig TeamMemberId {
  // Primitive type: string
  value: String
}


sig FileTransfersTransferViewType {
  description: String,
}


sig TwoAccountChangePolicyDetails {
  new_value: TwoAccountPolicy,
  previous_value: lone TwoAccountPolicy,
}


sig GroupDescriptionUpdatedType {
  description: String,
}


sig UploadApiRateLimitValue {
  tag: String,
}


sig MemberAddResult {
  tag: String,
}


sig ListFileMembersCountResult {
  member_count: Int,
  members: SharedFileMembers,
}


sig FileCommentNotificationPolicy {
  tag: String,
}


sig TeamEncryptionKeyCancelKeyDeletionType {
  description: String,
}


sig GroupJoinPolicy {
  tag: String,
}


sig ObjectLabelAddedType {
  description: String,
}


sig FolderMetadata {
  // Generic object with no specific type
}


sig SharingAllowlistRemoveArgs {
  emails: set String,
  domains: set String,
}


sig AccountCaptureChangeAvailabilityType {
  description: String,
}


sig UploadWriteFailed {
  reason: WriteError,
  upload_session_id: String,
}


sig ShowcaseExternalSharingPolicy {
  tag: String,
}


sig ListMembersDevicesResult {
  has_more: Bool,
  devices: set MemberDevices,
  cursor: lone String,
}


sig UserInfo {
  team_member_id: lone String,
  account_id: AccountId,
  email: String,
  display_name: String,
  same_team: Bool,
}


sig AddPropertiesArg {
  property_groups: set PropertyGroup,
  path: PathOrId,
}


sig ApplyNamingConventionDetails {
}


sig TeamProfileChangeBackgroundDetails {
}


sig EndedEnterpriseAdminSessionDetails {
}


sig UsersSelectorArg {
  tag: String,
}


sig EndedEnterpriseAdminSessionType {
  description: String,
}


sig SharedContentChangeLinkPasswordDetails {
}


sig PaperDocumentLogInfo {
  doc_id: String,
  doc_title: String,
}


sig MicrosoftOfficeAddinPolicy {
  tag: String,
}


sig AuthError {
  tag: String,
}


sig PaperUpdateResult {
  paper_revision: Int,
}


sig ExcludedUsersListContinueError {
  tag: String,
}


sig DeleteBatchResultEntry {
  tag: String,
}


sig TeamNamespacesListContinueError {
  tag: String,
}


sig FileTransfersTransferSendDetails {
  file_transfer_id: String,
}


sig ListFoldersResult {
  cursor: lone String,
  entries: set SharedFolderMetadata,
}


sig TemplateFilter {
  tag: String,
}


sig SharedLinkMetadata {
  id: lone Id,
  link_permissions: LinkPermissions,
  url: String,
  expires: lone DropboxTimestamp,
  name: String,
  team_member_info: lone TeamMemberInfo,
  path_lower: lone String,
  content_owner_team_info: lone TeamInfo,
}


sig ListFileRequestsResult {
  file_requests: set FileRequest,
}


sig SsoChangeLoginUrlType {
  description: String,
}


sig TeamMergeToDetails {
  team_name: String,
}


sig DateRangeError {
  tag: String,
}


sig PaperDocChangeSubscriptionType {
  description: String,
}


sig FileTransfersFileAddType {
  description: String,
}


sig NamePart {
  // Primitive type: string
  value: String
}


sig SharedContentRelinquishMembershipDetails {
}


sig UserSecondaryEmailsArg {
  secondary_emails: set EmailAddress,
  user: UserSelectorArg,
}


sig AdminAlertingAlertSensitivity {
  tag: String,
}


sig ExcludedUsersUpdateError {
  tag: String,
}


sig DisabledDomainInvitesDetails {
}


sig WebSessionsFixedLengthPolicy {
  tag: String,
}


sig ExpectedSharedContentLinkMetadata {
  // Generic object with no specific type
}


sig SharedLinkAlreadyExistsMetadata {
  tag: String,
}


sig FileUnresolveCommentDetails {
  comment_text: lone String,
}


sig PaperDesktopPolicyChangedType {
  description: String,
}


sig TokenFromOAuth1Result {
  oauth2_token: String,
}


sig TeamFolderRenameArg {
  // Generic object with no specific type
}


sig ExternalDriveBackupPolicy {
  tag: String,
}


sig InsufficientQuotaAmounts {
  space_needed: Int,
  space_left: Int,
  space_shortage: Int,
}


sig ListFilesContinueArg {
  cursor: String,
}


sig SearchResult {
  matches: set SearchMatch,
  more: Bool,
  start: Int,
}


sig SharedFolderMembers {
  invitees: set InviteeMembershipInfo,
  cursor: lone String,
  users: set UserMembershipInfo,
  groups: set GroupMembershipInfo,
}


sig GetFileRequestArgs {
  id: FileRequestId,
}


sig TwoAccountChangePolicyType {
  description: String,
}


sig TeamMemberProfile {
  // Generic object with no specific type
}


sig SsoAddLogoutUrlType {
  description: String,
}


sig UserQuota {
  // Primitive type: integer
  value: Int
}


sig ExportFormat {
  tag: String,
}


sig PaperPublishedLinkCreateType {
  description: String,
}


sig AllowDownloadEnabledType {
  description: String,
}


sig ExtendedVersionHistoryPolicy {
  tag: String,
}


sig GroupChangeMemberRoleDetails {
  is_group_owner: Bool,
}


sig DeviceLinkSuccessDetails {
  device_session_info: lone DeviceSessionLogInfo,
}


sig ReplayFileDeleteDetails {
}


sig MemberSetProfilePhotoDetails {
}


sig CreateSharedLinkWithSettingsArg {
  settings: lone SharedLinkSettings,
  path: ReadPath,
}


sig PasswordControlMode {
  tag: String,
}


sig AccountCapturePolicy {
  tag: String,
}


sig DownloadPolicyType {
  tag: String,
}


sig ExcludedUsersListArg {
  limit: Int,
}


sig ExternalDriveBackupStatus {
  tag: String,
}


sig LinkAudienceOption {
  audience: LinkAudience,
  allowed: Bool,
  disallowed_reason: lone LinkAudienceDisallowedReason,
}


sig SharedLinkCreatePolicy {
  tag: String,
}


sig MembersTransferFormerMembersFilesError {
  tag: String,
}


sig PaperPublishedLinkChangePermissionDetails {
  event_uuid: String,
  new_permission_level: String,
  previous_permission_level: String,
}


sig LinkPassword {
  tag: String,
}


sig SharedContentRemoveLinkPasswordDetails {
}


sig MemberChangeStatusDetails {
  action: lone ActionDetails,
  new_team: lone String,
  previous_value: lone MemberStatus,
  previous_team: lone String,
  new_value: MemberStatus,
}


sig PaperDocAddCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig MemberPermission {
  reason: lone PermissionDeniedReason,
  action: MemberAction,
  allow: Bool,
}


sig PasswordStrengthRequirementsChangePolicyDetails {
  previous_value: PasswordStrengthPolicy,
  new_value: PasswordStrengthPolicy,
}


sig ShowcaseEditedType {
  description: String,
}


sig SharingChangeMemberPolicyDetails {
  previous_value: lone SharingMemberPolicy,
  new_value: SharingMemberPolicy,
}


sig SharingAllowlistRemoveError {
  tag: String,
}


sig AddSecondaryEmailResult {
  tag: String,
}


sig SharedLinkSettingsRemovePasswordType {
  description: String,
}


sig MemberChangeMembershipTypeType {
  description: String,
}


sig ShowcaseViewDetails {
  event_uuid: String,
}


sig GetMetadataArg {
  include_property_groups: lone TemplateFilterBase,
  path: ReadPath,
  include_has_explicit_shared_members: Bool,
  include_media_info: Bool,
  include_deleted: Bool,
}


sig TfaAddSecurityKeyDetails {
}


sig CaptureTranscriptPolicyChangedType {
  description: String,
}


sig ReadPath {
  // Generic object with no specific type
}


sig CreateSharedLinkArg {
  path: String,
  pending_upload: lone PendingUploadMode,
  short_url: Bool,
}


sig ShmodelDisableDownloadsDetails {
  shared_link_owner: lone UserLogInfo,
}


sig PasswordChangeType {
  description: String,
}


sig PlatformType {
  tag: String,
}


sig PaperPublishedLinkChangePermissionType {
  description: String,
}


sig FileTransfersPolicyChangedType {
  description: String,
}


sig AddTemplateArg {
  // Generic object with no specific type
}


sig SharingAllowlistListContinueArg {
  cursor: String,
}


sig PaperDocUpdateArgs {
  // Generic object with no specific type
}


sig TfaAddExceptionDetails {
}


sig CaptureTranscriptPolicyChangedDetails {
  new_value: CaptureTranscriptPolicy,
  previous_value: CaptureTranscriptPolicy,
}


sig LockFileResult {
  metadata: Metadata,
  lock: FileLock,
}


sig PathR {
  // Primitive type: string
  value: String
}


sig ListMemberAppsError {
  tag: String,
}


sig AdminEmailRemindersPolicy {
  tag: String,
}


sig MemberSuggestionsPolicy {
  tag: String,
}


sig Visibility {
  tag: String,
}


sig SfFbInviteChangeRoleType {
  description: String,
}


sig RelocationBatchResult {
  // Generic object with no specific type
}


sig FileRequestCloseDetails {
  file_request_id: lone FileRequestId,
  previous_details: lone FileRequestDetails,
}


sig SharingChangeLinkPolicyType {
  description: String,
}


sig TeamFolderListContinueError {
  tag: String,
}


sig ListUsersOnPaperDocArgs {
  // Generic object with no specific type
}


sig EmmRefreshAuthTokenDetails {
}


sig SignInAsSessionStartDetails {
}


sig SearchMatch {
  match_type: SearchMatchType,
  metadata: Metadata,
}


sig TeamMergeRequestAutoCanceledDetails {
  details: lone String,
}


sig ReplayFileDeleteType {
  description: String,
}


sig PropertyFieldTemplate {
  name: String,
  type: PropertyType,
  description: String,
}


sig ShowcaseUntrashedDeprecatedType {
  description: String,
}


sig AsyncJobId {
  // Primitive type: string
  value: String
}


sig ApiApp {
  publisher_url: lone String,
  linked: lone DropboxTimestamp,
  is_app_folder: Bool,
  app_id: String,
  app_name: String,
  publisher: lone String,
}


sig SearchOrderBy {
  tag: String,
}


sig ListFolderLongpollError {
  tag: String,
}


sig FolderSubscriptionLevel {
  tag: String,
}


sig ListMemberDevicesArg {
  include_desktop_clients: Bool,
  team_member_id: String,
  include_web_sessions: Bool,
  include_mobile_clients: Bool,
}


sig WebSessionsChangeActiveSessionLimitType {
  description: String,
}


sig TeamMergeRequestAcceptedShownToSecondaryTeamType {
  description: String,
}


sig TeamMemberInfoV2 {
  profile: TeamMemberProfile,
  roles: set TeamMemberRole,
}


sig RestoreArg {
  rev: Rev,
  path: WritePath,
}


sig MemberDeleteManualContactsDetails {
}


sig FileEditCommentDetails {
  comment_text: lone String,
  previous_comment_text: String,
}


sig FileDownloadType {
  description: String,
}


sig TeamEncryptionKeyScheduleKeyDeletionDetails {
}


sig PaperDocViewDetails {
  event_uuid: String,
}


sig MemberChangeExternalIdType {
  description: String,
}


sig EnterpriseSettingsLockingType {
  description: String,
}


sig GetTagsArg {
  paths: set Path,
}


sig UpdateFolderMemberError {
  tag: String,
}


sig ExternalDriveBackupPolicyState {
  tag: String,
}


sig IntegrationDisconnectedType {
  description: String,
}


sig DeviceApprovalsRemoveExceptionType {
  description: String,
}


sig SharingPublicPolicyType {
  tag: String,
}


sig TeamMergeFromDetails {
  team_name: String,
}


sig MembersGetInfoV2Result {
  members_info: set MembersGetInfoItemV2,
}


sig GroupsSelector {
  tag: String,
}


sig FileRequestsEmailsEnabledType {
  description: String,
}


sig UploadSessionFinishBatchJobStatus {
  tag: String,
}


sig SsoChangeSamlIdentityModeType {
  description: String,
}


sig PaperDocDownloadType {
  description: String,
}


sig NoPasswordLinkViewReportFailedType {
  description: String,
}


sig RateLimitReason {
  tag: String,
}


sig AccountCaptureMigrateAccountDetails {
  domain_name: String,
}


sig GetFileMetadataBatchResult {
  result: GetFileMetadataIndividualResult,
  file: PathOrId,
}


sig FolderLinkRestrictionPolicy {
  tag: String,
}


sig LegalHoldId {
  // Primitive type: string
  value: String
}


sig InviteeMembershipInfo {
  // Generic object with no specific type
}


sig StartedEnterpriseAdminSessionDetails {
  federation_extra_details: FedExtraDetails,
}


sig AdminAlertCategoryEnum {
  tag: String,
}


sig UnlockFileArg {
  path: WritePathOrId,
}


sig SfAllowNonMembersToViewSharedLinksDetails {
  target_asset_index: Int,
  original_folder_name: String,
  shared_folder_type: lone String,
}


sig FileAddFromAutomationDetails {
}


sig GroupChangeExternalIdType {
  description: String,
}


sig ResellerSupportSessionEndType {
  description: String,
}


sig SfTeamUninviteType {
  description: String,
}


sig Certificate {
  serial_number: String,
  common_name: lone String,
  subject: String,
  issue_date: String,
  expiration_date: String,
  sha1_fingerprint: String,
  issuer: String,
}


sig AdminEmailRemindersChangedDetails {
  new_value: AdminEmailRemindersPolicy,
  previous_value: AdminEmailRemindersPolicy,
}


sig SharedFolderChangeMembersPolicyType {
  description: String,
}


sig CreateSharedLinkError {
  tag: String,
}


sig SmartSyncOptOutType {
  description: String,
}


sig Tag {
  tag: String,
}


sig RevokeDesktopClientArg {
  // Generic object with no specific type
}


sig LinkSettings {
  password: lone LinkPassword,
  audience: lone LinkAudience,
  access_level: lone AccessLevel,
  expiry: lone LinkExpiry,
}


sig ShowcaseResolveCommentType {
  description: String,
}


sig EmmChangePolicyType {
  description: String,
}


sig SfAddGroupType {
  description: String,
}


sig SecondaryEmailVerifiedType {
  description: String,
}


sig GroupId {
  // Primitive type: string
  value: String
}


sig PaperContentRenameDetails {
  event_uuid: String,
}


sig DeleteBatchError {
  tag: String,
}


sig MemberDeleteProfilePhotoDetails {
}


sig Dimensions {
  width: Int,
  height: Int,
}


sig PaperContentCreateType {
  description: String,
}


sig PaperChangeMemberPolicyType {
  description: String,
}


sig GetTemporaryUploadLinkResult {
  link: String,
}


sig PathLinkMetadata {
  // Generic object with no specific type
}


sig ListFolderMembersContinueError {
  tag: String,
}


sig GetAccountBatchArg {
  account_ids: set AccountId,
}


sig TeamFolderChangeStatusDetails {
  new_value: TeamFolderStatus,
  previous_value: lone TeamFolderStatus,
}


sig PolicyType {
  tag: String,
}


sig PropertiesSearchError {
  tag: String,
}


sig MemberTransferAccountContentsDetails {
}


sig IntegrationPolicy {
  tag: String,
}


sig PathLogInfo {
  namespace_relative: NamespaceRelativePathLogInfo,
  contextual: lone FilePath,
}


sig LoginFailDetails {
  login_method: LoginMethod,
  is_emm_managed: lone Bool,
  error_details: FailureDetailsLogInfo,
}


sig TeamSelectiveSyncPolicyChangedType {
  description: String,
}


sig FileUnresolveCommentType {
  description: String,
}


sig ListMembersAppsArg {
  cursor: lone String,
}


sig GovernancePolicyReportCreatedType {
  description: String,
}


sig SharedLinkSettingsAddExpirationType {
  description: String,
}


sig SingleUserLock {
  lock_holder_team_id: lone String,
  created: DropboxTimestamp,
  lock_holder_account_id: AccountId,
}


sig SecondaryEmailVerifiedDetails {
  secondary_email: EmailAddress,
}


sig FileLockingPolicyChangedDetails {
  previous_value: FileLockingPolicyState,
  new_value: FileLockingPolicyState,
}


sig ChangeLinkExpirationPolicy {
  tag: String,
}


sig RelocationPath {
  from_path: WritePathOrId,
  to_path: WritePathOrId,
}


sig VisibilityPolicyDisallowedReason {
  tag: String,
}


sig CreateFolderBatchArg {
  force_async: Bool,
  paths: set WritePath,
  autorename: Bool,
}


sig LegalHoldsError {
  tag: String,
}


sig ListUsersOnFolderArgs {
  // Generic object with no specific type
}


sig PaperPublishedLinkDisabledType {
  description: String,
}


sig BinderRenamePageType {
  description: String,
}


sig MalformedPathError {
  // Primitive type: string
  value: String
}


sig DownloadZipResult {
  metadata: FolderMetadata,
}


sig SharedLinkPolicy {
  tag: String,
}


sig LinkAccessLevel {
  tag: String,
}


sig FileMetadata {
  // Generic object with no specific type
}


sig DeviceApprovalsChangeOverageActionType {
  description: String,
}


sig AddPaperDocUser {
  // Generic object with no specific type
}


sig TfaAddSecurityKeyType {
  description: String,
}


sig ListFileMembersBatchResult {
  file: PathOrId,
  result: ListFileMembersIndividualResult,
}


sig PaperDocPermissionLevel {
  tag: String,
}


sig FileLock {
  content: FileLockContent,
}


sig PaperDocFollowedDetails {
  event_uuid: String,
}


sig BinderAddSectionDetails {
  binder_item_name: String,
  event_uuid: String,
  doc_title: String,
}


sig GroupSummary {
  group_management_type: GroupManagementType,
  group_id: GroupId,
  group_name: String,
  group_external_id: lone GroupExternalId,
  member_count: lone Int,
}


sig TeamMergeRequestReminderDetails {
  request_reminder_details: TeamMergeRequestReminderExtraDetails,
}


sig RemoveFolderMemberArg {
  leave_a_copy: Bool,
  member: MemberSelector,
  shared_folder_id: SharedFolderId,
}


sig SearchMatchV2 {
  highlight_spans: set HighlightSpan,
  metadata: MetadataV2,
  match_type: lone SearchMatchTypeV2,
}


sig LockFileBatchResult {
  // Generic object with no specific type
}


sig DeleteAllClosedFileRequestsError {
  tag: String,
}


sig PaperExternalViewForbidDetails {
  event_uuid: String,
}


sig AppPermissionsChangedDetails {
  app_name: lone String,
  permission: lone AdminConsoleAppPermission,
  previous_value: AdminConsoleAppPolicy,
  new_value: AdminConsoleAppPolicy,
}


sig PaperDocUnresolveCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig NoteShareReceiveDetails {
}


sig DomainInvitesApproveRequestToJoinTeamType {
  description: String,
}


sig UndoNamingConventionType {
  description: String,
}


sig OverwritePropertyGroupArg {
  property_groups: set PropertyGroup,
  path: PathOrId,
}


sig ShowcaseUntrashedType {
  description: String,
}


sig GetTemporaryLinkError {
  tag: String,
}


sig SharingAllowlistListError {
}


sig GetMetadataArgs {
  actions: set FolderAction,
  shared_folder_id: SharedFolderId,
}


sig GroupDeleteDetails {
  is_company_managed: lone Bool,
}


sig AccessError {
  tag: String,
}


sig UserFileMembershipInfo {
  // Generic object with no specific type
}


sig ListPaperDocsFilterBy {
  tag: String,
}


sig FileAction {
  tag: String,
}


sig FileRequestsChangePolicyDetails {
  new_value: FileRequestsPolicy,
  previous_value: lone FileRequestsPolicy,
}


sig GroupRenameType {
  description: String,
}


sig MemberSpaceLimitsRemoveCustomQuotaType {
  description: String,
}


sig TeamId {
  // Primitive type: string
  value: String
}


sig SharingAllowlistListContinueError {
  tag: String,
}


sig DeviceDeleteOnUnlinkSuccessType {
  description: String,
}


sig RevokeDeviceSessionStatus {
  error_type: lone RevokeDeviceSessionError,
  success: Bool,
}


sig AppId {
  // Primitive type: string
  value: String
}


sig FileRequestChangeDetails {
  new_details: FileRequestDetails,
  file_request_id: lone FileRequestId,
  previous_details: lone FileRequestDetails,
}


sig UploadSessionFinishBatchResult {
  entries: set UploadSessionFinishBatchResultEntry,
}


sig ClassificationPolicyEnumWrapper {
  tag: String,
}


sig CollectionLinkMetadata {
  // Generic object with no specific type
}


sig CommitInfo {
  mode: WriteMode,
  property_groups: set PropertyGroup,
  strict_conflict: Bool,
  autorename: Bool,
  client_modified: lone DropboxTimestamp,
  mute: Bool,
  path: WritePathOrId,
}


sig SearchMode {
  tag: String,
}


sig CreateFolderBatchLaunch {
  tag: String,
}


sig TeamMemberRole {
  description: String,
  role_id: TeamMemberRoleId,
  name: String,
}


sig ShareFolderJobStatus {
  tag: String,
}


sig GroupMembersRemoveArg {
  // Generic object with no specific type
}


sig RelocationBatchResultEntry {
  tag: String,
}


sig GuestAdminChangeStatusDetails {
  new_value: TrustedTeamsRequestState,
  guest_team_name: lone String,
  previous_value: TrustedTeamsRequestState,
  host_team_name: lone String,
  is_guest: Bool,
  action_details: TrustedTeamsRequestAction,
}


sig UploadSessionFinishBatchResultEntry {
  tag: String,
}


sig NoteSharedDetails {
}


sig PaperFolderCreateResult {
  folder_id: String,
}


sig ExportError {
  tag: String,
}


sig TeamMergeRequestSentShownToSecondaryTeamType {
  description: String,
}


sig GroupAddExternalIdType {
  description: String,
}


sig PaperDocUpdateError {
  tag: String,
}


sig ListPaperDocsContinueArgs {
  cursor: String,
}


sig GroupDeleteType {
  description: String,
}


sig ActorLogInfo {
  tag: String,
}


sig MemberSpaceLimitsAddCustomQuotaType {
  description: String,
}


sig ShowcaseRemoveMemberType {
  description: String,
}


sig TfaAddExceptionType {
  description: String,
}


sig DomainInvitesRequestToJoinTeamDetails {
}


sig DeviceDeleteOnUnlinkFailDetails {
  session_info: lone SessionLogInfo,
  display_name: lone String,
  num_failures: Int,
}


sig WritePath {
  // Primitive type: string
  value: String
}


sig FileRequestReceiveFileDetails {
  submitter_name: lone DisplayNameLegacy,
  file_request_id: lone FileRequestId,
  file_request_details: lone FileRequestDetails,
  submitted_file_names: set String,
  submitter_email: lone EmailAddress,
}


sig SendForSignaturePolicy {
  tag: String,
}


sig ListTeamAppsResult {
  apps: set MemberLinkedApps,
  has_more: Bool,
  cursor: lone String,
}


sig PropertiesSearchResult {
  matches: set PropertiesSearchMatch,
  cursor: lone PropertiesSearchCursor,
}


sig DeviceUnlinkPolicy {
  tag: String,
}


sig TeamMergeRequestExpiredExtraDetails {
  tag: String,
}


sig SharingChangeMemberPolicyType {
  description: String,
}


sig MemberAccess {
  access_type: GroupAccessType,
  user: UserSelectorArg,
}


sig PaperPublishedLinkCreateDetails {
  event_uuid: String,
}


sig TeamMemberLogInfo {
  // Generic object with no specific type
}


sig FileMemberActionError {
  tag: String,
}


sig ViewerInfoPolicyChangedType {
  description: String,
}


sig FileAddType {
  description: String,
}


sig PaperContentRemoveFromFolderType {
  description: String,
}


sig ContentSyncSettingArg {
  sync_setting: SyncSettingArg,
  id: FileId,
}


sig LegalHoldsPolicyUpdateResult {
  // Generic object with no specific type
}


sig NoPasswordLinkViewCreateReportDetails {
  start_date: DropboxTimestamp,
  end_date: DropboxTimestamp,
}


sig SharedLinkCopyDetails {
  shared_link_owner: lone UserLogInfo,
}


sig ShowcaseResolveCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig LoginSuccessType {
  description: String,
}


sig PaperContentArchiveType {
  description: String,
}


sig GetThumbnailBatchResultData {
  metadata: FileMetadata,
  thumbnail: String,
}


sig MembersRemoveError {
  tag: String,
}


sig UserRootInfo {
  // Generic object with no specific type
}


sig SharedContentChangeMemberRoleDetails {
  previous_access_level: lone AccessLevel,
  new_access_level: AccessLevel,
}


sig GroupsListContinueError {
  tag: String,
}


sig TeamFolderRenameType {
  description: String,
}


sig TeamSharingPolicies {
  group_creation_policy: GroupCreation,
  shared_link_create_policy: SharedLinkCreatePolicy,
  shared_folder_join_policy: SharedFolderJoinPolicy,
  shared_folder_link_restriction_policy: SharedFolderBlanketLinkRestrictionPolicy,
  shared_folder_member_policy: SharedFolderMemberPolicy,
}


sig TfaChangeStatusDetails {
  new_value: TfaConfiguration,
  previous_value: lone TfaConfiguration,
  used_rescue_code: lone Bool,
}


sig CreateFolderError {
  tag: String,
}


sig TeamMergeRequestCanceledDetails {
  request_canceled_details: TeamMergeRequestCanceledExtraDetails,
}


sig FileDownloadDetails {
}


sig FileRequestsEmailsRestrictedToTeamOnlyDetails {
}


sig DomainInvitesApproveRequestToJoinTeamDetails {
}


sig MemberPermanentlyDeleteAccountContentsType {
  description: String,
}


sig BinderRenameSectionType {
  description: String,
}


sig MemberSpaceLimitsAddExceptionDetails {
}


sig LegalHoldsListPoliciesArg {
  include_released: Bool,
}


sig PermanentDeleteChangePolicyDetails {
  previous_value: lone ContentPermanentDeletePolicy,
  new_value: ContentPermanentDeletePolicy,
}


sig ActionDetails {
  tag: String,
}


sig UndoOrganizeFolderWithTidyDetails {
}


sig ShowcaseUntrashedDetails {
  event_uuid: String,
}


sig PropertiesSearchArg {
  queries: set PropertiesSearchQuery,
  template_filter: TemplateFilter,
}


sig TeamMembershipType {
  tag: String,
}


sig GroupMovedType {
  description: String,
}


sig SsoPolicy {
  tag: String,
}


sig ObjectLabelRemovedType {
  description: String,
}


sig LegalHoldsExportRemovedDetails {
  name: String,
  legal_hold_id: String,
  export_name: String,
}


sig DropboxPasswordsNewDeviceEnrolledDetails {
  platform: String,
  is_first_device: Bool,
}


sig GovernancePolicyExportRemovedType {
  description: String,
}


sig SecondaryEmail {
  // Generic object with no specific type
}


sig FileRequestCreateDetails {
  file_request_id: lone FileRequestId,
  request_details: lone FileRequestDetails,
}


sig AdminAlertingTriggeredAlertDetails {
  alert_category: AdminAlertCategoryEnum,
  alert_name: String,
  alert_instance_id: String,
  alert_severity: AdminAlertSeverityEnum,
}


sig SearchMatchTypeV2 {
  tag: String,
}


sig AddPaperDocUserResult {
  tag: String,
}


sig LinkAudience {
  tag: String,
}


sig ListHeldRevisionCursor {
  // Primitive type: string
  value: String
}


sig ShowcasePermanentlyDeletedDetails {
  event_uuid: String,
}


sig TemplateFilterBase {
  tag: String,
}


sig SsoRemoveCertDetails {
}


sig MembersGetInfoItemV2 {
  tag: String,
}


sig LegalHoldsReportAHoldType {
  description: String,
}


sig MembersDataTransferArg {
  // Generic object with no specific type
}


sig LegalHoldStatus {
  tag: String,
}


sig ShareFolderLaunch {
  tag: String,
}


sig FileLockMetadata {
  created: lone DropboxTimestamp,
  lockholder_account_id: lone AccountId,
  is_lockholder: lone Bool,
  lockholder_name: lone String,
}


sig TeamFolderUpdateSyncSettingsArg {
  // Generic object with no specific type
}


sig PaperUpdateError {
  tag: String,
}


sig PaperDocTeamInviteDetails {
  event_uuid: String,
}


sig GroupCreateArg {
  add_creator_as_owner: Bool,
  group_name: String,
  group_external_id: lone GroupExternalId,
  group_management_type: lone GroupManagementType,
}


sig LegalHoldsExportAHoldType {
  description: String,
}


sig ExternalSharingCreateReportType {
  description: String,
}


sig RelocationBatchJobStatus {
  tag: String,
}


sig DeleteSecondaryEmailsResult {
  results: set UserDeleteResult,
}


sig SharedContentClaimInvitationDetails {
  shared_content_link: lone String,
}


sig AccountType {
  tag: String,
}


sig GroupMembersSelector {
  group: GroupSelector,
  users: UsersSelectorArg,
}


sig MembersRecoverArg {
  user: UserSelectorArg,
}


sig CreateFolderArg {
  path: WritePath,
  autorename: Bool,
}


sig FileMemberActionIndividualResult {
  tag: String,
}


sig AppLinkTeamDetails {
  app_info: AppLogInfo,
}


sig TeamSharingWhitelistSubjectsChangedDetails {
  added_whitelist_subjects: set String,
  removed_whitelist_subjects: set String,
}


sig PropertyGroupUpdate {
  template_id: TemplateId,
  add_or_update_fields: set PropertyField,
  remove_fields: set String,
}


sig FileRevertType {
  description: String,
}


sig TrustedTeamsRequestState {
  tag: String,
}


sig AudienceRestrictingSharedFolder {
  shared_folder_id: SharedFolderId,
  name: String,
  audience: LinkAudience,
}


sig MembersSetProfilePhotoArg {
  photo: PhotoSourceArg,
  user: UserSelectorArg,
}


sig MediaMetadata {
  time_taken: lone DropboxTimestamp,
  location: lone GpsCoordinates,
  dimensions: lone Dimensions,
}


sig DomainVerificationAddDomainFailDetails {
  domain_name: String,
  verification_method: lone String,
}


sig MemberChangeMembershipTypeDetails {
  prev_value: TeamMembershipType,
  new_value: TeamMembershipType,
}


sig WebSessionsChangeActiveSessionLimitDetails {
  new_value: String,
  previous_value: String,
}


sig IntegrationPolicyChangedType {
  description: String,
}


sig MountFolderError {
  tag: String,
}


sig TokenFromOAuth1Error {
  tag: String,
}


sig PaperDocTeamInviteType {
  description: String,
}


sig LabelType {
  tag: String,
}


sig GovernancePolicyCreateType {
  description: String,
}


sig DeviceApprovalsChangeOverageActionDetails {
  previous_value: lone RolloutMethod,
  new_value: lone RolloutMethod,
}


sig LoginMethod {
  tag: String,
}


sig SharedContentRemoveMemberType {
  description: String,
}


sig DropboxPasswordsPolicyChangedType {
  description: String,
}


sig DomainInvitesEmailExistingUsersDetails {
  domain_name: String,
  num_recipients: Int,
}


sig GuestAdminSignedInViaTrustedTeamsDetails {
  team_name: lone String,
  trusted_team_name: lone String,
}


sig TeamRootInfo {
  // Generic object with no specific type
}


sig DeletedMetadata {
  // Generic object with no specific type
}


sig ParticipantLogInfo {
  tag: String,
}


sig ModifySharedLinkSettingsError {
  tag: String,
}


sig DeviceApprovalsChangeMobilePolicyType {
  description: String,
}


sig GetSharedLinksError {
  tag: String,
}


sig SharedFolderNestDetails {
  new_ns_path: lone FilePath,
  previous_ns_path: lone FilePath,
  new_parent_ns_id: lone NamespaceId,
  previous_parent_ns_id: lone NamespaceId,
}


sig LegalHoldPolicyDescription {
  // Primitive type: string
  value: String
}


sig PaperDocUntrashedType {
  description: String,
}


sig MobileDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig CreateFolderEntryResult {
  metadata: FolderMetadata,
}


sig SharingTeamPolicyType {
  tag: String,
}


sig PaperFolderCreateArg {
  name: String,
  is_team_folder: lone Bool,
  parent_folder_id: lone String,
}


sig NamespaceType {
  tag: String,
}


sig SearchArg {
  query: String,
  mode: SearchMode,
  max_results: Int,
  start: Int,
  path: PathROrId,
}


sig SearchV2Result {
  has_more: Bool,
  cursor: lone SearchV2Cursor,
  matches: set SearchMatchV2,
}


sig NonTeamMemberLogInfo {
  // Generic object with no specific type
}


sig PaperDocDeleteCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig LockConflictError {
  lock: FileLock,
}


sig SfTeamJoinDetails {
  target_asset_index: Int,
  original_folder_name: String,
}


sig SharedFolderTransferOwnershipDetails {
  new_owner_email: EmailAddress,
  previous_owner_email: lone EmailAddress,
}


sig TeamProfileRemoveLogoType {
  description: String,
}


sig FileOpsResult {
}


sig FileDeleteCommentDetails {
  comment_text: lone String,
}


sig SharedContentChangeLinkAudienceType {
  description: String,
}


sig TimeUnit {
  tag: String,
}


sig GroupMembershipInfo {
  // Generic object with no specific type
}


sig UploadSessionOffsetError {
  correct_offset: Int,
}


sig TeamNamespacesListError {
  tag: String,
}


sig PassPolicy {
  tag: String,
}


sig CreateTeamInviteLinkType {
  description: String,
}


sig SearchV2ContinueArg {
  cursor: SearchV2Cursor,
}


sig LockFileArg {
  path: WritePathOrId,
}


sig DeviceApprovalsChangeDesktopPolicyType {
  description: String,
}


sig SharedContentChangeLinkExpiryType {
  description: String,
}


sig ListFolderError {
  tag: String,
}


sig GroupRemoveExternalIdDetails {
  previous_value: GroupExternalId,
}


sig MembersAddArgBase {
  force_async: Bool,
}


sig CreateFileRequestArgs {
  description: lone String,
  title: String,
  deadline: lone FileRequestDeadline,
  destination: Path,
  open: Bool,
}


sig GetFileMetadataIndividualResult {
  tag: String,
}


sig SsoChangeLogoutUrlDetails {
  previous_value: lone String,
  new_value: lone String,
}


sig AdminAlertingAlertStateChangedType {
  description: String,
}


sig GetAccountArg {
  account_id: AccountId,
}


sig MoveIntoVaultError {
  tag: String,
}


sig ListMembersDevicesError {
  tag: String,
}


sig SharedLinkCreateDetails {
  shared_link_access_level: lone SharedLinkAccessLevel,
}


sig DropboxPasswordsPolicyChangedDetails {
  new_value: DropboxPasswordsPolicy,
  previous_value: DropboxPasswordsPolicy,
}


sig ResellerSupportSessionStartType {
  description: String,
}


sig GetThumbnailBatchError {
  tag: String,
}


sig FileTransfersTransferDownloadType {
  description: String,
}


sig SharedContentRemoveLinkExpiryType {
  description: String,
}


sig ViewerInfoPolicy {
  tag: String,
}


sig EmmAddExceptionType {
  description: String,
}


sig RecipientsConfiguration {
  groups: set String,
  emails: set EmailAddress,
  recipient_setting_type: lone AlertRecipientsSettingType,
}


sig MemberAddArg {
  // Generic object with no specific type
}


sig SharedLinkDownloadDetails {
  shared_link_owner: lone UserLogInfo,
}


sig ListPaperDocsSortOrder {
  tag: String,
}


sig TeamMergeRequestCanceledType {
  description: String,
}


sig FedExtraDetails {
  tag: String,
}


sig NetworkControlChangePolicyDetails {
  new_value: NetworkControlPolicy,
  previous_value: lone NetworkControlPolicy,
}


sig AccountState {
  tag: String,
}


sig ShowcasePermanentlyDeletedType {
  description: String,
}


sig UserSecondaryEmailsResult {
  results: set AddSecondaryEmailResult,
  user: UserSelectorArg,
}


sig MembersDeactivateError {
  tag: String,
}


sig AccountCaptureRelinquishAccountType {
  description: String,
}


sig ShowcaseUnresolveCommentType {
  description: String,
}


sig DeviceDeleteOnUnlinkSuccessDetails {
  display_name: lone String,
  session_info: lone SessionLogInfo,
}


sig ExternalSharingCreateReportDetails {
}


sig SfFbUninviteDetails {
  original_folder_name: String,
  target_asset_index: Int,
}


sig LegalHoldsRemoveMembersType {
  description: String,
}


sig ShowcaseEditCommentType {
  description: String,
}


sig TeamMergeRequestSentShownToPrimaryTeamType {
  description: String,
}


sig SharedLinkVisibility {
  tag: String,
}


sig SharedLinkSettingsChangePasswordType {
  description: String,
}


sig SharedContentAddLinkPasswordType {
  description: String,
}


sig UploadSessionStartBatchArg {
  num_sessions: Int,
  session_type: lone UploadSessionType,
}


sig MemberSpaceLimitsChangeCustomQuotaType {
  description: String,
}


sig RequestedLinkAccessLevel {
  tag: String,
}


sig MembersAddJobStatus {
  tag: String,
}


sig MountFolderArg {
  shared_folder_id: SharedFolderId,
}


sig GetTeamEventsResult {
  has_more: Bool,
  events: set TeamEvent,
  cursor: String,
}


sig ShmodelEnableDownloadsType {
  description: String,
}


sig PaperUpdateArg {
  path: WritePathOrId,
  import_format: ImportFormat,
  paper_revision: lone Int,
  doc_update_policy: PaperDocUpdatePolicy,
}


sig TeamProfileChangeDefaultLanguageDetails {
  new_value: LanguageCode,
  previous_value: LanguageCode,
}


sig DomainInvitesSetInviteNewUserPrefToYesType {
  description: String,
}


sig RelocationBatchArgBase {
  entries: set RelocationPath,
  autorename: Bool,
}


sig ClassificationCreateReportDetails {
}


sig RevokeDeviceSessionBatchArg {
  revoke_devices: set RevokeDeviceSessionArg,
}


sig PhotoMetadata {
  // Generic object with no specific type
}


sig FileEditCommentType {
  description: String,
}


sig DeleteAllClosedFileRequestsResult {
  file_requests: set FileRequest,
}


sig ReplayProjectTeamAddType {
  description: String,
}


sig ExternalDriveBackupStatusChangedDetails {
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
  previous_value: ExternalDriveBackupStatus,
  new_value: ExternalDriveBackupStatus,
}


sig ResellerSupportChangePolicyDetails {
  new_value: ResellerSupportPolicy,
  previous_value: ResellerSupportPolicy,
}


sig DeleteTeamInviteLinkDetails {
  link_url: String,
}


sig AssetLogInfo {
  tag: String,
}


sig NetworkControlPolicy {
  tag: String,
}


sig GetStorageReport {
  // Generic object with no specific type
}


sig ListFoldersContinueError {
  tag: String,
}


sig ActiveWebSession {
  // Generic object with no specific type
}


sig AddMemberSelectorError {
  tag: String,
}


sig RewindFolderDetails {
  rewind_folder_target_ts_ms: DropboxTimestamp,
}


sig SecondaryTeamRequestExpiredDetails {
  sent_to: String,
}


sig SharedContentChangeLinkAudienceDetails {
  previous_value: lone LinkAudience,
  new_value: LinkAudience,
}


sig PaperPublishedLinkViewType {
  description: String,
}


sig DeviceApprovalsChangeDesktopPolicyDetails {
  previous_value: lone DeviceApprovalsPolicy,
  new_value: lone DeviceApprovalsPolicy,
}


sig SearchOptions {
  account_id: lone AccountId,
  file_status: FileStatus,
  order_by: lone SearchOrderBy,
  path: lone PathROrId,
  max_results: Int,
  filename_only: Bool,
  file_categories: set FileCategory,
  file_extensions: set String,
}


sig SharingAllowlistAddArgs {
  emails: set String,
  domains: set String,
}


sig PaperDocEditCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig TeamActivityCreateReportDetails {
  start_date: DropboxTimestamp,
  end_date: DropboxTimestamp,
}


sig LegalHoldPolicy {
  status: LegalHoldStatus,
  end_date: lone DropboxTimestamp,
  members: MembersInfo,
  description: lone LegalHoldPolicyDescription,
  activation_time: lone DropboxTimestamp,
  id: LegalHoldId,
  start_date: DropboxTimestamp,
  name: LegalHoldPolicyName,
}


sig FileCopyType {
  description: String,
}


sig UnlockFileBatchArg {
  entries: set UnlockFileArg,
}


sig WatermarkingPolicyChangedDetails {
  previous_value: WatermarkingPolicy,
  new_value: WatermarkingPolicy,
}


sig AllowDownloadEnabledDetails {
}


sig FileSaveCopyReferenceDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig HasTeamFileEventsValue {
  tag: String,
}


sig PaperContentRemoveMemberType {
  description: String,
}


sig SharedFolderChangeMembersManagementPolicyType {
  description: String,
}


sig EmmErrorType {
  description: String,
}


sig OrganizeFolderWithTidyDetails {
}


sig SsoChangeLogoutUrlType {
  description: String,
}


sig UnmountFolderError {
  tag: String,
}


sig ContentPermanentDeletePolicy {
  tag: String,
}


sig AddSecondaryEmailsError {
  tag: String,
}


sig SharedFolderMetadata {
  // Generic object with no specific type
}


sig FileRequestCreateType {
  description: String,
}


sig LoginSuccessDetails {
  login_method: LoginMethod,
  is_emm_managed: lone Bool,
}


sig DeviceApprovalsChangeUnlinkActionType {
  description: String,
}


sig TeamEncryptionKeyCancelKeyDeletionDetails {
}


sig LinkExpiry {
  tag: String,
}


sig FileProviderMigrationPolicyState {
  tag: String,
}


sig DropboxPasswordsExportedDetails {
  platform: String,
}


sig SharedLinkChangeExpiryType {
  description: String,
}


sig FilePermission {
  reason: lone PermissionDeniedReason,
  action: FileAction,
  allow: Bool,
}


sig NoPasswordLinkGenReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig RansomwareRestoreProcessStartedType {
  description: String,
}


sig FileCommentsPolicy {
  tag: String,
}


sig TeamMergeFromType {
  description: String,
}


sig SharedContentUnshareDetails {
}


sig SharedFolderChangeMembersManagementPolicyDetails {
  new_value: AclUpdatePolicy,
  previous_value: lone AclUpdatePolicy,
}


sig DeviceApprovalsPolicy {
  tag: String,
}


sig ListFolderContinueArg {
  cursor: ListFolderCursor,
}


sig CreateFolderBatchResult {
  // Generic object with no specific type
}


sig TeamInfo {
  // Generic object with no specific type
}


sig DeviceChangeIpMobileDetails {
  device_session_info: lone DeviceSessionLogInfo,
}


sig NoteShareReceiveType {
  description: String,
}


sig FileUnlikeCommentType {
  description: String,
}


sig TeamProfileAddBackgroundDetails {
}


sig GovernancePolicyEditDetailsType {
  description: String,
}


sig BinderAddSectionType {
  description: String,
}


sig SmartSyncCreateAdminPrivilegeReportType {
  description: String,
}


sig SmartSyncCreateAdminPrivilegeReportDetails {
}


sig TeamMergeToType {
  description: String,
}


sig TwoAccountPolicy {
  tag: String,
}


sig CustomQuotaResult {
  tag: String,
}


sig SharingAllowlistRemoveResponse {
}


sig ThumbnailError {
  tag: String,
}


sig EmmAddExceptionDetails {
}


sig AclUpdatePolicy {
  tag: String,
}


sig GovernancePolicyEditDurationDetails {
  governance_policy_id: String,
  name: String,
  new_value: DurationLogInfo,
  policy_type: lone PolicyType,
  previous_value: DurationLogInfo,
}


sig FileStatus {
  tag: String,
}


sig FileTransfersTransferDeleteType {
  description: String,
}


sig GroupRenameDetails {
  previous_value: String,
  new_value: String,
}


sig PaperExternalViewDefaultTeamType {
  description: String,
}


sig DropboxPasswordsPolicy {
  tag: String,
}


sig SymlinkInfo {
  target: String,
}


sig PaperDocMentionType {
  description: String,
}


sig SharedFolderMemberError {
  tag: String,
}


sig MembersSetPermissions2Result {
  team_member_id: TeamMemberId,
  roles: set TeamMemberRole,
}


sig UnshareFileError {
  tag: String,
}


sig TeamFolderCreateError {
  tag: String,
}


sig ComputerBackupPolicyChangedType {
  description: String,
}


sig HasTeamSharedDropboxValue {
  tag: String,
}


sig LegalHoldsPolicyCreateError {
  tag: String,
}


sig SharingMemberPolicy {
  tag: String,
}


sig TeamMergeRequestExpiredDetails {
  request_expired_details: TeamMergeRequestExpiredExtraDetails,
}


sig BinderRemovePageType {
  description: String,
}


sig SharedLinkChangeVisibilityType {
  description: String,
}


sig SharedLinkError {
  tag: String,
}


sig SharedLinkSettingsAllowDownloadEnabledDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig WebSessionsChangeFixedLengthPolicyDetails {
  new_value: lone WebSessionsFixedLengthPolicy,
  previous_value: lone WebSessionsFixedLengthPolicy,
}


sig RelocationError {
  tag: String,
}


sig FileGetCopyReferenceType {
  description: String,
}


sig MemberSendInvitePolicyChangedType {
  description: String,
}


sig JoinTeamDetails {
  linked_apps: set UserLinkedAppLogInfo,
  has_linked_shared_folders: lone Bool,
  has_linked_devices: lone Bool,
  linked_shared_folders: set FolderLogInfo,
  was_linked_devices_truncated: lone Bool,
  was_linked_shared_folders_truncated: lone Bool,
  was_linked_apps_truncated: lone Bool,
  has_linked_apps: lone Bool,
  linked_devices: set LinkedDeviceLogInfo,
}


sig MemberSpaceLimitsRemoveExceptionType {
  description: String,
}


sig UserDeleteEmailsResult {
  user: UserSelectorArg,
  results: set DeleteSecondaryEmailResult,
}


sig UploadSessionCursor {
  offset: Int,
  session_id: String,
}


sig RemoveTemplateArg {
  template_id: TemplateId,
}


sig SmartSyncNotOptOutDetails {
  previous_value: SmartSyncOptOutPolicy,
  new_value: SmartSyncOptOutPolicy,
}


sig DeviceDeleteOnUnlinkFailType {
  description: String,
}


sig WriteError {
  tag: String,
}


sig ListUsersOnPaperDocResponse {
  has_more: Bool,
  cursor: Cursor,
  invitees: set InviteeInfoWithPermissionLevel,
  users: set UserInfoWithPermissionLevel,
  doc_owner: UserInfo,
}


sig PropertiesSearchMode {
  tag: String,
}


sig PropertyGroupTemplate {
  fields: set PropertyFieldTemplate,
  description: String,
  name: String,
}


sig JobStatus {
  tag: String,
}


sig DateRange {
  end_date: lone Date,
  start_date: lone Date,
}


sig GroupsGetInfoItem {
  tag: String,
}


sig ShmodelGroupShareDetails {
}


sig DropboxPasswordsNewDeviceEnrolledType {
  description: String,
}


sig ResendVerificationEmailResult {
  results: set UserResendResult,
}


sig TeamProfileChangeNameType {
  description: String,
}


sig FileProviderMigrationPolicyChangedDetails {
  previous_value: FileProviderMigrationPolicyState,
  new_value: FileProviderMigrationPolicyState,
}


sig DeviceSession {
  updated: lone DropboxTimestamp,
  country: lone String,
  ip_address: lone String,
  session_id: String,
  created: lone DropboxTimestamp,
}


sig MemberSpaceLimitType {
  tag: String,
}


sig GroupMembersSelectorError {
  tag: String,
}


sig DataResidencyMigrationRequestSuccessfulType {
  description: String,
}


sig SaveUrlError {
  tag: String,
}


sig MembershipInfo {
  access_type: AccessLevel,
  permissions: set MemberPermission,
  initials: lone String,
  is_inherited: Bool,
}


sig GroupMembersSetAccessTypeArg {
  // Generic object with no specific type
}


sig FileResolveCommentType {
  description: String,
}


sig SharedContentUnshareType {
  description: String,
}


sig ListTeamDevicesArg {
  include_desktop_clients: Bool,
  cursor: lone String,
  include_mobile_clients: Bool,
  include_web_sessions: Bool,
}


sig MemberSpaceLimitsAddExceptionType {
  description: String,
}


sig LinkMetadata {
  visibility: Visibility,
  url: String,
  expires: lone DropboxTimestamp,
}


sig Feature {
  tag: String,
}


sig LegalHoldsGetPolicyArg {
  id: LegalHoldId,
}


sig InviteeInfoWithPermissionLevel {
  invitee: InviteeInfo,
  permission_level: PaperDocPermissionLevel,
}


sig UserInfoError {
  tag: String,
}


sig RolloutMethod {
  tag: String,
}


sig ListFolderArg {
  shared_link: lone SharedLink,
  include_media_info: Bool,
  path: PathROrId,
  include_non_downloadable_files: Bool,
  include_deleted: Bool,
  include_mounted_folders: Bool,
  recursive: Bool,
  limit: lone Int,
  include_property_groups: lone TemplateFilterBase,
  include_has_explicit_shared_members: Bool,
}


sig TeamSelectiveSyncPolicyChangedDetails {
  previous_value: TeamSelectiveSyncPolicy,
  new_value: TeamSelectiveSyncPolicy,
}


sig DefaultLinkExpirationDaysPolicy {
  tag: String,
}


sig UploadSessionFinishBatchArg {
  entries: set UploadSessionFinishArg,
}


sig BaseDfbReport {
  start_date: String,
}


sig ListFilesResult {
  cursor: lone String,
  entries: set SharedFileMetadata,
}


sig ShowcasePostCommentType {
  description: String,
}


sig SsoChangeCertType {
  description: String,
}


sig SharedContentAddMemberType {
  description: String,
}


sig PaperFolderTeamInviteType {
  description: String,
}


sig CreateFolderEntryError {
  tag: String,
}


sig SignInAsSessionEndType {
  description: String,
}


sig ListFolderLongpollResult {
  changes: Bool,
  backoff: lone Int,
}


sig SaveCopyReferenceError {
  tag: String,
}


sig SharedLinkCopyType {
  description: String,
}


sig TeamBrandingPolicy {
  tag: String,
}


sig InviteeInfo {
  tag: String,
}


sig ReplayFileSharedLinkModifiedType {
  description: String,
}


sig UserFeaturesGetValuesBatchResult {
  values: set UserFeatureValue,
}


sig ShowcaseArchivedType {
  description: String,
}


sig GroupMembersAddArg {
  // Generic object with no specific type
}


sig PrimaryTeamRequestExpiredDetails {
  secondary_team: String,
  sent_by: String,
}


sig GetTemporaryLinkResult {
  metadata: FileMetadata,
  link: String,
}


sig FileLockingLockStatusChangedType {
  description: String,
}


sig PaperDocRevertType {
  description: String,
}


sig TfaChangePolicyType {
  description: String,
}


sig AppUnlinkUserDetails {
  app_info: AppLogInfo,
}


sig SharedFolderAccessError {
  tag: String,
}


sig FolderOverviewDescriptionChangedDetails {
  folder_overview_location_asset: Int,
}


sig FileLockContent {
  tag: String,
}


sig ReplayProjectTeamAddDetails {
}


sig TfaConfiguration {
  tag: String,
}


sig DeviceLinkSuccessType {
  description: String,
}


sig ChangedEnterpriseAdminRoleDetails {
  new_value: FedAdminRole,
  team_name: String,
  previous_value: FedAdminRole,
}


sig ExternalDriveBackupEligibilityStatusCheckedDetails {
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
  number_of_external_drive_backup: Int,
  status: ExternalDriveBackupEligibilityStatus,
}


sig RootInfo {
  root_namespace_id: NamespaceId,
  home_namespace_id: NamespaceId,
}


sig FileSaveCopyReferenceType {
  description: String,
}


sig EmailIngestReceiveFileType {
  description: String,
}


sig MembersListContinueError {
  tag: String,
}


sig TeamEncryptionKeyDisableKeyDetails {
}


sig SharedLinkShareType {
  description: String,
}


sig GroupMovedDetails {
}


sig AppUnlinkTeamDetails {
  app_info: AppLogInfo,
}


sig PasswordResetType {
  description: String,
}


sig ListFolderMembersArgs {
  // Generic object with no specific type
}


sig GetSharedLinkFileError {
  tag: String,
}


sig FileLockingLockStatusChangedDetails {
  previous_value: LockStatus,
  new_value: LockStatus,
}


sig OpenIdError {
  tag: String,
}


sig ResendVerificationEmailArg {
  emails_to_resend: set UserSecondaryEmailsArg,
}


sig SharedLinkSettingsChangeAudienceType {
  description: String,
}


sig LockFileBatchArg {
  entries: set LockFileArg,
}


sig CreateFolderDetails {
}


sig LaunchEmptyResult {
  tag: String,
}


sig UserResendEmailsResult {
  user: UserSelectorArg,
  results: set ResendSecondaryEmailResult,
}


sig DeviceChangeIpDesktopType {
  description: String,
}


sig GroupsListResult {
  groups: set GroupSummary,
  cursor: String,
  has_more: Bool,
}


sig ShowcaseViewType {
  description: String,
}


sig UploadSessionFinishError {
  tag: String,
}


sig DeviceLinkFailType {
  description: String,
}


sig FileLockingPolicyChangedType {
  description: String,
}


sig SetProfilePhotoResult {
  profile_photo_url: String,
}


sig MemberSpaceLimitsChangeStatusDetails {
  previous_value: SpaceLimitsStatus,
  new_value: SpaceLimitsStatus,
}


sig PaperFolderFollowedDetails {
  event_uuid: String,
}


sig EnforceLinkPasswordPolicy {
  tag: String,
}


sig MembersListError {
  tag: String,
}


sig GuestAdminSignedOutViaTrustedTeamsDetails {
  trusted_team_name: lone String,
  team_name: lone String,
}


sig DomainInvitesSetInviteNewUserPrefToNoType {
  description: String,
}


sig PaperApiBaseError {
  tag: String,
}


sig GroupJoinPolicyUpdatedType {
  description: String,
}


sig ExcludedUsersUpdateArg {
  users: set UserSelectorArg,
}


sig TeamMergeRequestExpiredShownToSecondaryTeamDetails {
  sent_to: String,
}


sig MemberSpaceLimitsChangeStatusType {
  description: String,
}


sig PaperDocUpdatePolicy {
  tag: String,
}


sig GetThumbnailBatchArg {
  entries: set ThumbnailArg,
}


sig PaperDocChangeSharingPolicyDetails {
  public_sharing_policy: lone String,
  team_sharing_policy: lone String,
  event_uuid: String,
}


sig SharedContentDownloadDetails {
  shared_content_access_level: AccessLevel,
  shared_content_owner: lone UserLogInfo,
  shared_content_link: String,
}


sig PaperChangePolicyDetails {
  new_value: PaperEnabledPolicy,
  previous_value: lone PaperEnabledPolicy,
}


sig MembersSetPermissionsError {
  tag: String,
}


sig LegalHoldsGetPolicyResult {
  // Generic object with no specific type
}


sig SharedContentViewDetails {
  shared_content_link: String,
  shared_content_owner: lone UserLogInfo,
  shared_content_access_level: AccessLevel,
}


sig PaperDocChangeMemberRoleType {
  description: String,
}


sig PaperContentRenameType {
  description: String,
}


sig ExternalSharingReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig PropertiesError {
  tag: String,
}


sig ListSharedLinksError {
  tag: String,
}


sig PaperDocEditType {
  description: String,
}


sig ListFolderCursor {
  // Primitive type: string
  value: String
}


sig MemberStatus {
  tag: String,
}


sig TfaResetDetails {
}


sig SharedFolderUnmountType {
  description: String,
}


sig MemberLinkedApps {
  linked_api_apps: set ApiApp,
  team_member_id: String,
}


sig AdminConsoleAppPolicy {
  tag: String,
}


sig AdminAlertingAlertStatePolicy {
  tag: String,
}


sig PollArg {
  async_job_id: AsyncJobId,
}


sig PaperDocTrashedDetails {
  event_uuid: String,
}


sig MemberAddExternalIdDetails {
  new_value: MemberExternalId,
}


sig TeamFolderCreateDetails {
}


sig SharedContentChangeMemberRoleType {
  description: String,
}


sig NoPasswordLinkViewCreateReportType {
  description: String,
}


sig ClassificationCreateReportFailType {
  description: String,
}


sig MemberAddV2Arg {
  // Generic object with no specific type
}


sig NonTrustedTeamDetails {
  team: String,
}


sig DeviceManagementEnabledDetails {
}


sig RelocationResult {
  // Generic object with no specific type
}


sig TransferFolderError {
  tag: String,
}


sig PaperFolderCreateError {
  tag: String,
}


sig AdminAlertingChangedAlertConfigType {
  description: String,
}


sig ShowcaseChangeDownloadPolicyType {
  description: String,
}


sig AccessMethodLogInfo {
  tag: String,
}


sig ShowcaseChangeEnabledPolicyType {
  description: String,
}


sig InviteMethod {
  tag: String,
}


sig SharedContentChangeViewerInfoPolicyType {
  description: String,
}


sig ClassificationChangePolicyDetails {
  previous_value: ClassificationPolicyEnumWrapper,
  new_value: ClassificationPolicyEnumWrapper,
  classification_type: ClassificationType,
}


sig DeleteSecondaryEmailsArg {
  emails_to_delete: set UserSecondaryEmailsArg,
}


sig SharedFolderId {
  // Generic object with no specific type
}


sig GroupsMembersListContinueError {
  tag: String,
}


sig GovernancePolicyCreateDetails {
  duration: DurationLogInfo,
  folders: set String,
  policy_type: lone PolicyType,
  name: String,
  governance_policy_id: String,
}


sig FileAddDetails {
}


sig MemberRemoveExternalIdType {
  description: String,
}


sig AppUnlinkTeamType {
  description: String,
}


sig AddTagArg {
  path: Path,
  tag_text: TagText,
}


sig GroupChangeManagementTypeType {
  description: String,
}


sig GetSharedLinksResult {
  links: set LinkMetadata,
}


sig SsoAddCertDetails {
  certificate_details: Certificate,
}


sig SaveUrlJobStatus {
  tag: String,
}


sig EndedEnterpriseAdminSessionDeprecatedDetails {
  federation_extra_details: FedExtraDetails,
}


sig FileRequestChangeType {
  description: String,
}


sig SharedFolderMountType {
  description: String,
}


sig DeviceUnlinkType {
  description: String,
}


sig FederationStatusChangeAdditionalInfo {
  tag: String,
}


sig FileDeleteDetails {
}


sig ShowcaseAccessGrantedDetails {
  event_uuid: String,
}


sig OpenNoteSharedDetails {
}


sig SfTeamJoinType {
  description: String,
}


sig RequestId {
  // Primitive type: string
  value: String
}


sig SharedContentRelinquishMembershipType {
  description: String,
}


sig RestoreError {
  tag: String,
}


sig SfTeamJoinFromOobLinkType {
  description: String,
}


sig NoExpirationLinkGenCreateReportDetails {
  end_date: DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig AdminConsoleAppPermission {
  tag: String,
}


sig FileRequestId {
  // Primitive type: string
  value: String
}


sig UserCustomQuotaArg {
  user: UserSelectorArg,
  quota_gb: UserQuota,
}


sig DesktopDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig AdminAlertingTriggeredAlertType {
  description: String,
}


sig SharingAllowlistAddError {
  tag: String,
}


sig OutdatedLinkViewCreateReportDetails {
  end_date: DropboxTimestamp,
  start_date: DropboxTimestamp,
}


sig SpaceUsage {
  allocation: SpaceAllocation,
  used: Int,
}


sig TeamMergeRequestExpiredType {
  description: String,
}


sig LegalHoldsChangeHoldDetailsDetails {
  previous_value: String,
  legal_hold_id: String,
  name: String,
  new_value: String,
}


sig RemovePaperDocUser {
  // Generic object with no specific type
}


sig ListFolderLongpollArg {
  timeout: Int,
  cursor: ListFolderCursor,
}


sig GetThumbnailBatchResultEntry {
  tag: String,
}


sig LinkAction {
  tag: String,
}


sig FolderOverviewItemUnpinnedDetails {
  folder_overview_location_asset: Int,
  pinned_items_asset_indices: set Int,
}


sig DeleteError {
  tag: String,
}


sig RevokeLinkedAppBatchResult {
  revoke_linked_app_status: set RevokeLinkedAppStatus,
}


sig ShowcaseFileDownloadDetails {
  event_uuid: String,
  download_type: String,
}


sig SharedLinkSettingsChangeExpirationType {
  description: String,
}


sig MemberSpaceLimitsChangeCapsTypePolicyDetails {
  previous_value: SpaceCapsType,
  new_value: SpaceCapsType,
}


sig PasswordChangeDetails {
}


sig PropertiesSearchContinueError {
  tag: String,
}


sig ListFolderGetLatestCursorResult {
  cursor: ListFolderCursor,
}


sig AudienceExceptionContentInfo {
  name: String,
}


sig ExcludedUsersListError {
  tag: String,
}


sig SharedContentRestoreInviteesType {
  description: String,
}


sig NoteAclTeamLinkType {
  description: String,
}


sig PropertiesSearchMatch {
  path: String,
  id: Id,
  is_deleted: Bool,
  property_groups: set PropertyGroup,
}


sig PaperDesktopPolicyChangedDetails {
  previous_value: PaperDesktopPolicy,
  new_value: PaperDesktopPolicy,
}


sig ListRevisionsResult {
  entries: set FileMetadata,
  is_deleted: Bool,
  server_deleted: lone DropboxTimestamp,
}


sig FileMemberActionResult {
  sckey_sha1: lone String,
  invitation_signature: set String,
  member: MemberSelector,
  result: FileMemberActionIndividualResult,
}


sig SharedContentRequestAccessDetails {
  shared_content_link: lone String,
}


sig BackupInvitationOpenedType {
  description: String,
}


sig TeamFolderIdListArg {
  team_folder_ids: set SharedFolderId,
}


sig ListSharedLinksResult {
  links: set SharedLinkMetadata,
  has_more: Bool,
  cursor: lone String,
}


sig SharedLinkSettingsError {
  tag: String,
}


sig ListMembersAppsError {
  tag: String,
}


sig ExportArg {
  path: ReadPath,
  export_format: lone String,
}


sig SfExternalInviteWarnType {
  description: String,
}


sig SfTeamGrantAccessType {
  description: String,
}


sig SharedContentRemoveInviteesType {
  description: String,
}


sig SharedLinkRemoveExpiryType {
  description: String,
}


sig SsoRemoveLoginUrlType {
  description: String,
}


sig MemberChangeNameType {
  description: String,
}


sig CollectionShareType {
  description: String,
}


sig FedHandshakeAction {
  tag: String,
}


sig DesktopSessionLogInfo {
  // Generic object with no specific type
}


sig SearchMatchFieldOptions {
  include_highlights: Bool,
}


sig Account {
  profile_photo_url: lone String,
  name: Name,
  account_id: AccountId,
  disabled: Bool,
  email: String,
  email_verified: Bool,
}


sig ResellerLogInfo {
  reseller_name: String,
  reseller_email: EmailAddress,
}


sig DeviceManagementDisabledDetails {
}


sig ResellerSupportSessionEndDetails {
}


sig ComputerBackupPolicyChangedDetails {
  new_value: ComputerBackupPolicy,
  previous_value: ComputerBackupPolicy,
}


sig PaperDocSlackShareType {
  description: String,
}


sig MemberChangeResellerRoleDetails {
  new_value: ResellerRole,
  previous_value: ResellerRole,
}


sig CreateSharedLinkWithSettingsError {
  tag: String,
}


sig UserInfoResult {
  family_name: lone String,
  email: lone String,
  email_verified: lone Bool,
  iss: String,
  sub: String,
  given_name: lone String,
}


sig ListFileRequestsContinueArg {
  cursor: String,
}


sig GetTeamEventsContinueError {
  tag: String,
}


sig SetAccessInheritanceArg {
  access_inheritance: AccessInheritance,
  shared_folder_id: SharedFolderId,
}


sig EventCategory {
  tag: String,
}


sig MembersSetPermissionsResult {
  role: AdminTier,
  team_member_id: TeamMemberId,
}


sig EmmChangePolicyDetails {
  previous_value: lone EmmState,
  new_value: EmmState,
}


sig TeamMergeRequestReminderShownToSecondaryTeamDetails {
  sent_to: String,
}


sig UndoNamingConventionDetails {
}


sig ShowcaseFileRemovedDetails {
  event_uuid: String,
}


sig TfaChangePolicyDetails {
  previous_value: lone TwoStepVerificationPolicy,
  new_value: TwoStepVerificationPolicy,
}


sig PaperExternalViewDefaultTeamDetails {
  event_uuid: String,
}


sig ResellerId {
  // Primitive type: string
  value: String
}


sig UploadSessionLookupError {
  tag: String,
}


sig TeamMergeRequestCanceledShownToSecondaryTeamDetails {
  sent_to: String,
  sent_by: String,
}


sig GroupDescriptionUpdatedDetails {
}


sig TeamFolderInvalidStatusError {
  tag: String,
}


sig GetAccountBatchError {
  tag: String,
}


sig GracePeriod {
  tag: String,
}


sig ShowcaseAddMemberDetails {
  event_uuid: String,
}


sig ShowcaseAccessGrantedType {
  description: String,
}


sig MemberDeleteManualContactsType {
  description: String,
}


sig SharedContentRemoveLinkExpiryDetails {
  previous_value: lone DropboxTimestamp,
}


sig PaperExternalViewAllowType {
  description: String,
}


sig PaperEnabledUsersGroupAdditionType {
  description: String,
}


sig TeamMergeRequestReminderShownToPrimaryTeamType {
  description: String,
}


sig TeamMergeRequestAutoCanceledType {
  description: String,
}


sig DownloadZipArg {
  path: ReadPath,
}


sig SharingFileAccessError {
  tag: String,
}


sig UpdatePropertiesArg {
  path: PathOrId,
  update_property_groups: set PropertyGroupUpdate,
}


sig ResendSecondaryEmailResult {
  tag: String,
}


sig PaperDocDeleteCommentType {
  description: String,
}


sig ListFilesContinueError {
  tag: String,
}


sig ReplayFileSharedLinkModifiedDetails {
}


sig OutdatedLinkViewReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig FileCommentsChangePolicyDetails {
  new_value: FileCommentsPolicy,
  previous_value: lone FileCommentsPolicy,
}


sig PathRootError {
  tag: String,
}


sig SharedContentLinkMetadata {
  // Generic object with no specific type
}


sig PaperChangeDeploymentPolicyType {
  description: String,
}


sig EmmRemoveExceptionDetails {
}


sig RevokeLinkedApiAppArg {
  app_id: String,
  team_member_id: String,
  keep_app_folder: Bool,
}


sig RansomwareAlertCreateReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig LookUpPropertiesError {
  tag: String,
}


sig ShowcaseFileViewDetails {
  event_uuid: String,
}


sig PaperAdminExportStartType {
  description: String,
}


sig ListFileRequestsV2Result {
  has_more: Bool,
  file_requests: set FileRequest,
  cursor: String,
}


sig SaveUrlResult {
  tag: String,
}


sig RevokeDeviceSessionArg {
  tag: String,
}


sig PollResultBase {
  tag: String,
}


sig UploadArg {
  // Generic object with no specific type
}


sig SaveCopyReferenceArg {
  path: Path,
  copy_reference: String,
}


sig GovernancePolicyExportCreatedType {
  description: String,
}


sig FilePath {
  // Primitive type: string
  value: String
}


sig UpdateFolderMemberArg {
  access_level: AccessLevel,
  member: MemberSelector,
  shared_folder_id: SharedFolderId,
}


sig AppUnlinkUserType {
  description: String,
}


sig AppBlockedByPermissionsDetails {
  app_info: AppLogInfo,
}


sig SharedLinkCreateType {
  description: String,
}


sig FileDeleteType {
  description: String,
}


sig ShowcaseFileViewType {
  description: String,
}


sig GroupAddExternalIdDetails {
  new_value: GroupExternalId,
}


sig SearchError {
  tag: String,
}


sig BasicAccount {
  // Generic object with no specific type
}


sig GovernancePolicyReportCreatedDetails {
  governance_policy_id: String,
  policy_type: lone PolicyType,
  name: String,
}


sig SsoChangeSamlIdentityModeDetails {
  new_value: Int,
  previous_value: Int,
}


sig PendingSecondaryEmailAddedType {
  description: String,
}


sig TeamProfileChangeLogoType {
  description: String,
}


sig CreateFolderBatchJobStatus {
  tag: String,
}


sig FileRollbackChangesDetails {
}


sig AddMember {
  member: MemberSelector,
  access_level: AccessLevel,
}


sig TeamActivityCreateReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig SmartSyncNotOptOutType {
  description: String,
}


sig FileCategory {
  tag: String,
}


sig FileAddFromAutomationType {
  description: String,
}


sig SharedLink {
  password: lone String,
  url: SharedLinkUrl,
}


sig FileRenameType {
  description: String,
}


sig SharedFolderTransferOwnershipType {
  description: String,
}


sig ExternalDriveBackupEligibilityStatus {
  tag: String,
}


sig RequestedVisibility {
  tag: String,
}


sig MembersAddLaunch {
  tag: String,
}


sig TagText {
  // Primitive type: string
  value: String
}


sig OrganizationDetails {
  organization: String,
}


sig UserNameLogInfo {
  locale: lone String,
  given_name: String,
  surname: String,
}


sig SsoRemoveCertType {
  description: String,
}


sig GroupType {
  tag: String,
}


sig PaperApiCursorError {
  tag: String,
}


sig SsoRemoveLogoutUrlDetails {
  previous_value: String,
}


sig ViewerInfoPolicyChangedDetails {
  previous_value: PassPolicy,
  new_value: PassPolicy,
}


sig GovernancePolicyEditDetailsDetails {
  previous_value: String,
  name: String,
  attribute: String,
  new_value: String,
  governance_policy_id: String,
  policy_type: lone PolicyType,
}


sig TeamMergeRequestSentShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_to: String,
}


sig FeaturesGetValuesBatchArg {
  features: set Feature,
}


sig UserLinkedAppLogInfo {
  // Generic object with no specific type
}


sig SharedLinkAccessFailureReason {
  tag: String,
}


sig GroupsMembersListResult {
  members: set GroupMemberInfo,
  cursor: String,
  has_more: Bool,
}


sig UserLogInfo {
  display_name: lone DisplayNameLegacy,
  email: lone EmailAddress,
  account_id: lone AccountId,
}


sig BinderReorderPageDetails {
  event_uuid: String,
  doc_title: String,
  binder_item_name: String,
}


sig MobileClientSession {
  // Generic object with no specific type
}


sig TeamFolderCreateArg {
  name: String,
  sync_setting: lone SyncSettingArg,
}


sig PendingSecondaryEmailAddedDetails {
  secondary_email: EmailAddress,
}


sig ListRevisionsArg {
  mode: ListRevisionsMode,
  path: PathOrId,
  limit: Int,
}


sig GetTemporaryLinkArg {
  path: ReadPath,
}


sig UserCustomQuotaResult {
  quota_gb: lone UserQuota,
  user: UserSelectorArg,
}


sig DeviceChangeIpMobileType {
  description: String,
}


sig SendForSignaturePolicyChangedDetails {
  previous_value: SendForSignaturePolicy,
  new_value: SendForSignaturePolicy,
}


sig PaperDefaultFolderPolicyChangedDetails {
  previous_value: PaperDefaultFolderPolicy,
  new_value: PaperDefaultFolderPolicy,
}


sig MemberRequestsChangePolicyDetails {
  previous_value: lone MemberRequestsPolicy,
  new_value: MemberRequestsPolicy,
}


sig OutdatedLinkViewCreateReportType {
  description: String,
}


sig CreateFileRequestError {
  tag: String,
}


sig DomainInvitesSetInviteNewUserPrefToYesDetails {
}


sig PaperExternalViewAllowDetails {
  event_uuid: String,
}


sig CreateFolderBatchResultEntry {
  tag: String,
}


sig FileChangeCommentSubscriptionType {
  description: String,
}


sig SharedFolderChangeMembersInheritancePolicyDetails {
  previous_value: lone SharedFolderMembersInheritancePolicy,
  new_value: SharedFolderMembersInheritancePolicy,
}


sig UpdateFileRequestArgs {
  description: lone String,
  open: lone Bool,
  id: FileRequestId,
  title: lone String,
  destination: lone Path,
  deadline: UpdateFileRequestDeadline,
}


sig PaperDocCreateArgs {
  parent_folder_id: lone String,
  import_format: ImportFormat,
}


sig TfaChangeBackupPhoneType {
  description: String,
}


sig TrustedTeamsRequestAction {
  tag: String,
}


sig MemberAddResultBase {
  tag: String,
}


sig LegacyDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig CreateFolderResult {
  // Generic object with no specific type
}


sig NoExpirationLinkGenCreateReportType {
  description: String,
}


sig PaperFolderChangeSubscriptionDetails {
  event_uuid: String,
  new_subscription_level: String,
  previous_subscription_level: lone String,
}


sig TwoStepVerificationState {
  tag: String,
}


sig MemberChangeResellerRoleType {
  description: String,
}


sig FileRenameDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig UploadSessionAppendError {
  tag: String,
}


sig EmailIngestPolicyChangedDetails {
  previous_value: EmailIngestPolicy,
  new_value: EmailIngestPolicy,
}


sig FileMoveType {
  description: String,
}


sig GroupUpdateArgs {
  // Generic object with no specific type
}


sig PaperContentRestoreDetails {
  event_uuid: String,
}


sig GroupJoinPolicyUpdatedDetails {
  join_policy: lone GroupJoinPolicy,
  is_company_managed: lone Bool,
}


sig LockStatus {
  tag: String,
}


sig LegalHoldsChangeHoldNameType {
  description: String,
}


sig MemberAccessLevelResult {
  access_details: set ParentFolderAccessInfo,
  warning: lone String,
  access_level: lone AccessLevel,
}


sig GetActivityReport {
  // Generic object with no specific type
}


sig MemberSendInvitePolicyChangedDetails {
  new_value: MemberSendInvitePolicy,
  previous_value: MemberSendInvitePolicy,
}


sig RansomwareAlertCreateReportType {
  description: String,
}


sig JobError {
  tag: String,
}


sig RelocationBatchV2Launch {
  tag: String,
}


sig ThumbnailV2Error {
  tag: String,
}


sig SharedLinkUrl {
  // Primitive type: string
  value: String
}


sig ExcludedUsersUpdateResult {
  status: ExcludedUsersUpdateStatus,
}


sig ShareFolderErrorBase {
  tag: String,
}


sig ListFoldersContinueArg {
  cursor: String,
}


sig ThumbnailV2Arg {
  size: ThumbnailSize,
  resource: PathOrLink,
  format: ThumbnailFormat,
  mode: ThumbnailMode,
}


sig TeamBrandingPolicyChangedDetails {
  new_value: TeamBrandingPolicy,
  previous_value: TeamBrandingPolicy,
}


sig UserDeleteResult {
  tag: String,
}


sig ShowcaseTrashedDeprecatedDetails {
  event_uuid: String,
}


sig PropertiesSearchQuery {
  mode: PropertiesSearchMode,
  logical_operator: LogicalOperator,
  query: String,
}


sig SharedFolderDeclineInvitationDetails {
}


sig ShowcaseDocumentLogInfo {
  showcase_id: String,
  showcase_title: String,
}


sig FileRequestValidationError {
  // Primitive type: string
  value: String
}


sig MobileSessionLogInfo {
  // Generic object with no specific type
}


sig PaperDocDeletedType {
  description: String,
}


sig MembersRecoverError {
  tag: String,
}


sig GovernancePolicyExportCreatedDetails {
  policy_type: lone PolicyType,
  governance_policy_id: String,
  export_name: String,
  name: String,
}


sig SharedFolderDeclineInvitationType {
  description: String,
}


sig GovernancePolicyDeleteDetails {
  name: String,
  policy_type: lone PolicyType,
  governance_policy_id: String,
}


sig MembersDeleteProfilePhotoError {
  tag: String,
}


sig DirectoryRestrictionsAddMembersDetails {
}


sig RelocateAssetReferencesLogInfo {
  src_asset_index: Int,
  dest_asset_index: Int,
}


sig SfTeamInviteChangeRoleDetails {
  new_sharing_permission: lone String,
  target_asset_index: Int,
  previous_sharing_permission: lone String,
  original_folder_name: String,
}


sig SharedFolderBlanketLinkRestrictionPolicy {
  tag: String,
}


sig Name {
  display_name: String,
  surname: String,
  abbreviated_name: String,
  given_name: String,
  familiar_name: String,
}


sig PaperDesktopPolicy {
  tag: String,
}


sig SsoRemoveLoginUrlDetails {
  previous_value: String,
}


sig RelocationBatchV2Result {
  // Generic object with no specific type
}


sig RevokeLinkedAppBatchError {
  tag: String,
}


sig AdminAlertingChangedAlertConfigDetails {
  previous_alert_config: AdminAlertingAlertConfiguration,
  new_alert_config: AdminAlertingAlertConfiguration,
  alert_name: String,
}


sig SharedFolderMetadataBase {
  owner_display_names: set String,
  parent_shared_folder_id: lone SharedFolderId,
  path_display: lone String,
  is_inside_team_folder: Bool,
  path_lower: lone String,
  owner_team: lone Team,
  parent_folder_name: lone String,
  access_type: AccessLevel,
  is_team_folder: Bool,
}


sig SharingChangeLinkDefaultExpirationPolicyDetails {
  new_value: DefaultLinkExpirationDaysPolicy,
  previous_value: lone DefaultLinkExpirationDaysPolicy,
}


sig SharedContentChangeDownloadsPolicyDetails {
  new_value: DownloadPolicyType,
  previous_value: lone DownloadPolicyType,
}


sig SharingChangeLinkEnforcePasswordPolicyDetails {
  previous_value: lone ChangeLinkExpirationPolicy,
  new_value: ChangeLinkExpirationPolicy,
}


sig RemoveFileMemberError {
  tag: String,
}


sig FolderOverviewDescriptionChangedType {
  description: String,
}


sig PaperDocTrashedType {
  description: String,
}


sig LinkPermissions {
  revoke_failure_reason: lone SharedLinkAccessFailureReason,
  team_restricts_comments: Bool,
  can_disallow_download: Bool,
  requested_visibility: lone RequestedVisibility,
  can_set_password: lone Bool,
  can_use_extended_sharing_controls: lone Bool,
  allow_download: Bool,
  link_access_level: lone LinkAccessLevel,
  resolved_visibility: lone ResolvedVisibility,
  can_revoke: Bool,
  effective_audience: lone LinkAudience,
  can_set_expiry: Bool,
  can_remove_expiry: Bool,
  can_allow_download: Bool,
  audience_options: set LinkAudienceOption,
  require_password: lone Bool,
  visibility_policies: set VisibilityPolicy,
  allow_comments: Bool,
  can_remove_password: lone Bool,
}


sig DownloadError {
  tag: String,
}


sig UpdatePropertiesError {
  tag: String,
}


sig ShmodelDisableDownloadsType {
  description: String,
}


sig RateLimitError {
  reason: RateLimitReason,
  retry_after: Int,
}


sig GoogleSsoPolicy {
  tag: String,
}


sig SharingChangeLinkDefaultExpirationPolicyType {
  description: String,
}


sig MemberRequestsPolicy {
  tag: String,
}


sig SetCustomQuotaError {
  tag: String,
}


sig CreateFolderType {
  description: String,
}


sig NamespaceId {
  // Primitive type: string
  value: String
}


sig EchoArg {
  query: String,
}


sig ListPaperDocsResponse {
  cursor: Cursor,
  doc_ids: set PaperDocId,
  has_more: Bool,
}


sig AddPaperDocUserMemberResult {
  result: AddPaperDocUserResult,
  member: MemberSelector,
}


sig LegalHoldsChangeHoldNameDetails {
  new_value: String,
  previous_value: String,
  legal_hold_id: String,
}


sig ListMemberDevicesError {
  tag: String,
}


sig MemberRemoveActionType {
  tag: String,
}


sig DispositionActionType {
  tag: String,
}


sig NumberPerDay {
  items: set Int
}


sig TeamBrandingPolicyChangedType {
  description: String,
}


sig SecondaryTeamRequestAcceptedDetails {
  primary_team: String,
  sent_by: String,
}


sig GovernancePolicyAddFoldersDetails {
  name: String,
  folders: set String,
  governance_policy_id: String,
  policy_type: lone PolicyType,
}


sig TeamEncryptionKeyDeleteKeyDetails {
}


sig GetFileMetadataArg {
  file: PathOrId,
  actions: set FileAction,
}


sig UploadSessionFinishArg {
  cursor: UploadSessionCursor,
  commit: CommitInfo,
  content_hash: lone Sha256HexHash,
}


sig FolderLogInfo {
  // Generic object with no specific type
}


sig LegalHoldsPolicyReleaseError {
  tag: String,
}


sig TokenScopeError {
  required_scope: String,
}


sig AppBlockedByPermissionsType {
  description: String,
}


sig Metadata {
  path_lower: lone String,
  name: String,
  path_display: lone String,
  parent_shared_folder_id: lone SharedFolderId,
  preview_url: lone String,
}


sig FullAccount {
  // Generic object with no specific type
}


sig TeamEncryptionKeyScheduleKeyDeletionType {
  description: String,
}


sig PaperDocOwnershipChangedType {
  description: String,
}


sig PaperFolderDeletedType {
  description: String,
}


sig SecondaryTeamRequestCanceledDetails {
  sent_by: String,
  sent_to: String,
}


sig TransferFolderArg {
  to_dropbox_id: DropboxId,
  shared_folder_id: SharedFolderId,
}


sig MemberSuggestDetails {
  suggested_members: set EmailAddress,
}


sig WebDeviceSessionLogInfo {
  // Generic object with no specific type
}


sig PaperAdminExportStartDetails {
}


sig SharingFolderJoinPolicy {
  tag: String,
}


sig MobileClientPlatform {
  tag: String,
}


sig FileRequestError {
  tag: String,
}


sig SyncSettingArg {
  tag: String,
}


sig TemplateError {
  tag: String,
}


sig SsoChangeCertDetails {
  new_certificate_details: Certificate,
  previous_certificate_details: lone Certificate,
}


sig ExternalDriveBackupPolicyChangedType {
  description: String,
}


sig SmarterSmartSyncPolicyState {
  tag: String,
}


sig SfFbInviteChangeRoleDetails {
  previous_sharing_permission: lone String,
  original_folder_name: String,
  target_asset_index: Int,
  new_sharing_permission: lone String,
}


sig GroupCreateError {
  tag: String,
}


sig SignInAsSessionEndDetails {
}


sig ExportMembersReportDetails {
}


sig AccountCaptureChangePolicyDetails {
  previous_value: lone AccountCapturePolicy,
  new_value: AccountCapturePolicy,
}


sig SecondaryMailsPolicyChangedDetails {
  new_value: SecondaryMailsPolicy,
  previous_value: SecondaryMailsPolicy,
}


sig SmartSyncOptOutPolicy {
  tag: String,
}


sig IntegrationConnectedType {
  description: String,
}


sig GroupMemberSetAccessTypeError {
  tag: String,
}


sig UpdateFileMemberArgs {
  file: PathOrId,
  member: MemberSelector,
  access_level: AccessLevel,
}


sig GroupsPollError {
  tag: String,
}


sig ExportResult {
  file_metadata: FileMetadata,
  export_metadata: ExportMetadata,
}


sig AppLogInfo {
  display_name: lone String,
  app_id: lone AppId,
}


sig PaperDocUntrashedDetails {
  event_uuid: String,
}


sig PaperCreateError {
  tag: String,
}


sig SyncSettingsError {
  tag: String,
}


sig FailureDetailsLogInfo {
  user_friendly_message: lone String,
  technical_error_message: lone String,
}


sig MembersGetInfoArgs {
  members: set UserSelectorArg,
}


sig DirectoryRestrictionsRemoveMembersDetails {
}


sig PaperDocUnresolveCommentType {
  description: String,
}


sig ReplayProjectTeamDeleteDetails {
}


sig SharedLinkDisableType {
  description: String,
}


sig ShowcaseFileAddedDetails {
  event_uuid: String,
}


sig UpdateFolderPolicyArg {
  acl_update_policy: lone AclUpdatePolicy,
  viewer_info_policy: lone ViewerInfoPolicy,
  link_settings: lone LinkSettings,
  member_policy: lone MemberPolicy,
  shared_link_policy: lone SharedLinkPolicy,
  actions: set FolderAction,
  shared_folder_id: SharedFolderId,
}


sig ShowcaseRequestAccessDetails {
  event_uuid: String,
}


sig GovernancePolicyZipPartDownloadedType {
  description: String,
}


sig UnshareFolderError {
  tag: String,
}


sig EndedEnterpriseAdminSessionDeprecatedType {
  description: String,
}


sig LegalHoldsListPoliciesResult {
  policies: set LegalHoldPolicy,
}


sig GoogleSsoChangePolicyType {
  description: String,
}


sig SsoChangeLoginUrlDetails {
  previous_value: String,
  new_value: String,
}


sig LegalHoldsAddMembersType {
  description: String,
}


sig ShowcaseDownloadPolicy {
  tag: String,
}


sig ListMemberAppsArg {
  team_member_id: String,
}


sig BaseTagError {
  tag: String,
}


sig MediaInfo {
  tag: String,
}


sig ShowcaseRenamedType {
  description: String,
}


sig DomainVerificationAddDomainFailType {
  description: String,
}


sig DataPlacementRestrictionChangePolicyType {
  description: String,
}


sig DeviceChangeIpDesktopDetails {
  device_session_info: DeviceSessionLogInfo,
}


sig PaperFolderDeletedDetails {
  event_uuid: String,
}


sig DeviceSessionLogInfo {
  ip_address: lone IpAddress,
  created: lone DropboxTimestamp,
  updated: lone DropboxTimestamp,
}


sig SharedLinkDisableDetails {
  shared_link_owner: lone UserLogInfo,
}


sig SharedFolderCreateDetails {
  target_ns_id: lone NamespaceId,
}


sig MemberTransferAccountContentsType {
  description: String,
}


sig TeamMergeRequestReminderShownToSecondaryTeamType {
  description: String,
}


sig MemberTransferredInternalFields {
  source_team_id: TeamId,
  target_team_id: TeamId,
}


sig GovernancePolicyRemoveFoldersType {
  description: String,
}


sig Folder {
  name: String,
  id: String,
}


sig FolderSharingPolicyType {
  tag: String,
}


sig NamespaceMetadata {
  namespace_type: NamespaceType,
  team_member_id: lone TeamMemberId,
  namespace_id: SharedFolderId,
  name: String,
}


sig SharedLinkSettingsChangeAudienceDetails {
  new_value: LinkAudience,
  previous_value: lone LinkAudience,
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig SharedFolderCreateType {
  description: String,
}


sig DeleteManualContactsArg {
  email_addresses: set EmailAddress,
}


sig TeamDetails {
  team: String,
}


sig GetTemplateArg {
  template_id: TemplateId,
}


sig TfaChangeStatusType {
  description: String,
}


sig RemovePropertiesError {
  tag: String,
}


sig TfaResetType {
  description: String,
}


sig MemberProfile {
  is_directory_restricted: lone Bool,
  profile_photo_url: lone String,
  external_id: lone String,
  account_id: lone AccountId,
  membership_type: TeamMembershipType,
  team_member_id: TeamMemberId,
  email_verified: Bool,
  name: Name,
  secondary_emails: set SecondaryEmail,
  persistent_id: lone String,
  email: String,
  status: TeamMemberStatus,
  invited_on: lone DropboxTimestamp,
  suspended_on: lone DropboxTimestamp,
  joined_on: lone DropboxTimestamp,
}


sig ContextLogInfo {
  tag: String,
}


sig ContentSyncSetting {
  id: FileId,
  sync_setting: SyncSetting,
}


sig BinderRemovePageDetails {
  binder_item_name: String,
  event_uuid: String,
  doc_title: String,
}


sig PaperEnabledUsersGroupRemovalType {
  description: String,
}


sig MembersSetPermissions2Arg {
  new_roles: set TeamMemberRoleId,
  user: UserSelectorArg,
}


sig PaperContentRemoveMemberDetails {
  event_uuid: String,
}


sig PermissionDeniedReason {
  tag: String,
}


sig GroupsGetInfoError {
  tag: String,
}


sig RelinquishFolderMembershipArg {
  shared_folder_id: SharedFolderId,
  leave_a_copy: Bool,
}


sig FilePreviewType {
  description: String,
}


sig RelocationBatchArg {
  // Generic object with no specific type
}


sig SecondaryMailsPolicyChangedType {
  description: String,
}


sig DirectoryRestrictionsAddMembersType {
  description: String,
}


sig ObjectLabelUpdatedValueType {
  description: String,
}


sig DataResidencyMigrationRequestUnsuccessfulType {
  description: String,
}


sig TrustedNonTeamMemberLogInfo {
  // Generic object with no specific type
}


sig ListPaperDocsSortBy {
  tag: String,
}


sig NoteAclLinkType {
  description: String,
}


sig TfaRemoveExceptionType {
  description: String,
}


sig IdentifierType {
  tag: String,
}


sig LegalHoldsRemoveMembersDetails {
  name: String,
  legal_hold_id: String,
}


sig GroupsMembersListContinueArg {
  cursor: String,
}


sig PaperDocOwnershipChangedDetails {
  event_uuid: String,
  old_owner_user_id: lone AccountId,
  new_owner_user_id: AccountId,
}


sig DeviceManagementEnabledType {
  description: String,
}


sig SharedLinkViewType {
  description: String,
}


sig AdminEmailRemindersChangedType {
  description: String,
}


sig ListFileRequestsContinueError {
  tag: String,
}


sig MemberSpaceLimitsRemoveCustomQuotaDetails {
}


sig DeviceSyncBackupStatusChangedDetails {
  previous_value: BackupStatus,
  desktop_device_session_info: DesktopDeviceSessionLogInfo,
  new_value: BackupStatus,
}


sig ShowcaseDeleteCommentType {
  description: String,
}


sig FileCopyDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig PreviewResult {
  file_metadata: lone FileMetadata,
  link_metadata: lone MinimalFileLinkMetadata,
}


sig PaperDocResolveCommentType {
  description: String,
}


sig SharedContentRequestAccessType {
  description: String,
}


sig UpdateFolderPolicyError {
  tag: String,
}


sig PaperCreateArg {
  path: Path,
  import_format: ImportFormat,
}


sig PrimaryTeamRequestAcceptedDetails {
  secondary_team: String,
  sent_by: String,
}


sig MoveBatchArg {
  // Generic object with no specific type
}


sig InviteAcceptanceEmailPolicy {
  tag: String,
}


sig LegalHoldsPolicyUpdateArg {
  id: LegalHoldId,
  members: set TeamMemberId,
  description: lone LegalHoldPolicyDescription,
  name: lone LegalHoldPolicyName,
}


sig GetDevicesReport {
  // Generic object with no specific type
}


sig MemberSpaceLimitsChangeCapsTypePolicyType {
  description: String,
}


sig TfaRemoveBackupPhoneDetails {
}


sig PaperFolderTeamInviteDetails {
  event_uuid: String,
}


sig FileLogInfo {
  // Generic object with no specific type
}


sig ExternalUserLogInfo {
  user_identifier: String,
  identifier_type: IdentifierType,
}


sig DeviceApprovalsAddExceptionType {
  description: String,
}


sig SharedLinkFileInfo {
  password: lone String,
  path: lone String,
  url: String,
}


sig SmartSyncPolicy {
  tag: String,
}


sig TeamFolderMetadata {
  name: String,
  is_team_shared_dropbox: Bool,
  content_sync_settings: set ContentSyncSetting,
  team_folder_id: SharedFolderId,
  status: TeamFolderStatus,
  sync_setting: SyncSetting,
}


sig MembersGetInfoV2Arg {
  members: set UserSelectorArg,
}


sig MembersSetPermissions2Error {
  tag: String,
}


sig ListMembersAppsResult {
  has_more: Bool,
  apps: set MemberLinkedApps,
  cursor: lone String,
}


sig MicrosoftOfficeAddinChangePolicyType {
  description: String,
}


sig TeamSelectiveSyncSettingsChangedType {
  description: String,
}


sig GetTemporaryUploadLinkArg {
  commit_info: CommitInfo,
  duration: Int,
}


sig UndoOrganizeFolderWithTidyType {
  description: String,
}


sig SfInviteGroupType {
  description: String,
}


sig DeleteBatchArg {
  entries: set DeleteArg,
}


sig GroupDeleteError {
  tag: String,
}


sig AccountCaptureNotificationEmailsSentType {
  description: String,
}


sig BinderAddPageType {
  description: String,
}


sig UserTagsRemovedDetails {
  values: set String,
}


sig SsoErrorDetails {
  error_details: FailureDetailsLogInfo,
}


sig MemberChangeNameDetails {
  previous_value: lone UserNameLogInfo,
  new_value: UserNameLogInfo,
}


sig PaperDocCreateUpdateResult {
  title: String,
  revision: Int,
  doc_id: String,
}


sig PaperContentRemoveFromFolderDetails {
  event_uuid: String,
  target_asset_index: lone Int,
  parent_asset_index: lone Int,
}


sig GroupUpdateError {
  tag: String,
}


sig SharedFolderUnmountDetails {
}


sig EnterpriseSettingsLockingDetails {
  team_name: String,
  previous_settings_page_locking_state: String,
  new_settings_page_locking_state: String,
  settings_page_name: String,
}


sig TeamLinkedAppLogInfo {
  // Generic object with no specific type
}


sig GetAccountBatchResult {
  items: set BasicAccount
}


sig AllowDownloadDisabledType {
  description: String,
}


sig UserFeature {
  tag: String,
}


sig SharedContentAddMemberDetails {
  shared_content_access_level: AccessLevel,
}


sig SpaceAllocation {
  tag: String,
}


sig FileRequest {
  is_open: Bool,
  url: String,
  description: lone String,
  created: DropboxTimestamp,
  file_count: Int,
  id: FileRequestId,
  title: String,
  destination: lone Path,
  deadline: lone FileRequestDeadline,
}


sig DeleteTeamInviteLinkType {
  description: String,
}


sig TeamMergeRequestRevokedType {
  description: String,
}


sig MemberChangeStatusType {
  description: String,
}


sig CameraUploadsPolicyChangedType {
  description: String,
}


sig PaperPublishedLinkDisabledDetails {
  event_uuid: String,
}


sig ShowcaseArchivedDetails {
  event_uuid: String,
}


sig SfTeamInviteChangeRoleType {
  description: String,
}


sig DisplayName {
  // Primitive type: string
  value: String
}


sig MemberDevices {
  mobile_clients: set MobileClientSession,
  web_sessions: set ActiveWebSession,
  desktop_clients: set DesktopClientSession,
  team_member_id: String,
}


sig SharedLinkSettingsChangePasswordDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig ShareFolderArgBase {
  path: WritePathOrId,
  access_inheritance: AccessInheritance,
  shared_link_policy: lone SharedLinkPolicy,
  force_async: Bool,
  acl_update_policy: lone AclUpdatePolicy,
  member_policy: lone MemberPolicy,
  viewer_info_policy: lone ViewerInfoPolicy,
}


sig AlphaGetMetadataArg {
  // Generic object with no specific type
}


sig ShowcaseChangeEnabledPolicyDetails {
  new_value: ShowcaseEnabledPolicy,
  previous_value: ShowcaseEnabledPolicy,
}


sig DeviceChangeIpWebDetails {
  user_agent: String,
}


sig EchoResult {
  result: String,
}


sig SharedFolderChangeLinkPolicyDetails {
  new_value: SharedLinkPolicy,
  previous_value: lone SharedLinkPolicy,
}


sig MembersAddArg {
  // Generic object with no specific type
}


sig AddTemplateResult {
  template_id: TemplateId,
}


sig GroupInfo {
  // Generic object with no specific type
}


sig GetSharedLinksArg {
  path: lone String,
}


sig TeamMergeRequestAcceptedDetails {
  request_accepted_details: TeamMergeRequestAcceptedExtraDetails,
}


sig NoExpirationLinkGenReportFailedDetails {
  failure_reason: TeamReportFailureReason,
}


sig LockFileError {
  tag: String,
}


sig EventType {
  tag: String,
}


sig GroupMembersRemoveError {
  tag: String,
}


sig SharedLinkSettingsAllowDownloadDisabledDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
}


sig ListFolderResult {
  has_more: Bool,
  entries: set Metadata,
  cursor: ListFolderCursor,
}


sig GroupAccessType {
  tag: String,
}


sig SearchMatchType {
  tag: String,
}


sig TeamFolderIdArg {
  team_folder_id: SharedFolderId,
}


sig RemoveTagError {
  tag: String,
}


sig OutdatedLinkViewReportFailedType {
  description: String,
}


sig SsoChangePolicyDetails {
  new_value: SsoPolicy,
  previous_value: lone SsoPolicy,
}


sig TeamFolderDowngradeDetails {
  target_asset_index: Int,
}


sig FileRequestsEmailsRestrictedToTeamOnlyType {
  description: String,
}


sig SaveCopyReferenceResult {
  metadata: Metadata,
}


sig FileLinkMetadata {
  // Generic object with no specific type
}


sig MembersDeleteProfilePhotoArg {
  user: UserSelectorArg,
}


sig GetSharedLinkFileArg {
  // Generic object with no specific type
}


sig GroupRemoveMemberDetails {
}


sig GetTagsResult {
  paths_to_tags: set PathToTags,
}


sig AudienceExceptions {
  exceptions: set AudienceExceptionContentInfo,
  count: Int,
}


sig MembersUnsuspendArg {
  user: UserSelectorArg,
}


sig TeamFolderPermanentlyDeleteDetails {
}


sig GroupChangeManagementTypeDetails {
  previous_value: lone GroupManagementType,
  new_value: GroupManagementType,
}


sig LookupError {
  tag: String,
}


sig DomainInvitesEmailExistingUsersType {
  description: String,
}


sig AdminTier {
  tag: String,
}


sig DesktopPlatform {
  tag: String,
}


sig PaperChangeDeploymentPolicyDetails {
  new_value: PaperDeploymentPolicy,
  previous_value: lone PaperDeploymentPolicy,
}


sig FileRequestDeadline {
  allow_late_uploads: lone String,
  deadline: lone DropboxTimestamp,
}


sig BinderRenameSectionDetails {
  binder_item_name: String,
  previous_binder_item_name: lone String,
  event_uuid: String,
  doc_title: String,
}


sig TfaAddBackupPhoneDetails {
}


sig ChangedEnterpriseAdminRoleType {
  description: String,
}


sig ListUsersOnPaperDocContinueArgs {
  // Generic object with no specific type
}


sig FileTransfersPolicy {
  tag: String,
}


sig RevokeSharedLinkError {
  tag: String,
}


sig ShowcaseDeleteCommentDetails {
  event_uuid: String,
  comment_text: lone String,
}


sig ConnectedTeamName {
  team: String,
}


sig TrustedNonTeamMemberType {
  tag: String,
}


sig TeamSpaceAllocation {
  allocated: Int,
  user_within_team_space_allocated: Int,
  used: Int,
  user_within_team_space_limit_type: MemberSpaceLimitType,
  user_within_team_space_used_cached: Int,
}


sig SsoAddCertType {
  description: String,
}


sig SsoAddLoginUrlDetails {
  new_value: String,
}


sig PaperContentArchiveDetails {
  event_uuid: String,
}


sig ListTeamAppsError {
  tag: String,
}


sig FileLikeCommentType {
  description: String,
}


sig FileMoveDetails {
  relocate_action_details: set RelocateAssetReferencesLogInfo,
}


sig PaperAsFilesValue {
  tag: String,
}


sig ExcludedUsersUpdateStatus {
  tag: String,
}


sig DownloadZipError {
  tag: String,
}


sig MemberAddNameType {
  description: String,
}


sig Team {
  id: String,
  name: String,
}


sig SharedFolderChangeMembersPolicyDetails {
  previous_value: lone MemberPolicy,
  new_value: MemberPolicy,
}


sig FileRequestCloseType {
  description: String,
}


sig SfInviteGroupDetails {
  target_asset_index: Int,
}


sig LanguageCode {
  // Primitive type: string
  value: String
}


sig ListFileMembersError {
  tag: String,
}


sig PaperContentCreateDetails {
  event_uuid: String,
}


sig ListMemberDevicesResult {
  desktop_client_sessions: set DesktopClientSession,
  mobile_client_sessions: set MobileClientSession,
  active_web_sessions: set ActiveWebSession,
}


sig PaperFolderChangeSubscriptionType {
  description: String,
}


sig TfaChangeBackupPhoneDetails {
}


sig TeamMergeRequestCanceledShownToSecondaryTeamType {
  description: String,
}


sig FileCommentsChangePolicyType {
  description: String,
}


sig ShowcaseRenamedDetails {
  event_uuid: String,
}


sig TimeRange {
  start_time: lone DropboxTimestamp,
  end_time: lone DropboxTimestamp,
}


sig MemberRequestsChangePolicyType {
  description: String,
}


sig Id {
  // Generic object with no specific type
}


sig HighlightSpan {
  is_highlighted: Bool,
  highlight_str: String,
}


sig TeamFolderListContinueArg {
  cursor: String,
}


sig TeamEncryptionKeyDeleteKeyType {
  description: String,
}


sig SmartSyncChangePolicyType {
  description: String,
}


sig ReplayFileSharedLinkCreatedType {
  description: String,
}


sig FoldersContainingPaperDoc {
  folder_sharing_policy_type: lone FolderSharingPolicyType,
  folders: set Folder,
}


sig PollEmptyResult {
  tag: String,
}


sig GetMembershipReport {
  // Generic object with no specific type
}


sig RemovedStatus {
  is_recoverable: Bool,
  is_disconnected: Bool,
}


sig SharedContentClaimInvitationType {
  description: String,
}


sig AddTagError {
  tag: String,
}


sig GetFileRequestError {
  tag: String,
}


sig RemoveMemberJobStatus {
  tag: String,
}


sig RelinquishFolderMembershipError {
  tag: String,
}


sig MemberChangeAdminRoleType {
  description: String,
}


sig SharedLinkViewDetails {
  shared_link_owner: lone UserLogInfo,
}


sig FeaturesGetValuesBatchError {
  tag: String,
}


sig TeamProfileAddLogoDetails {
}


sig TeamFolderDowngradeType {
  description: String,
}


sig SetProfilePhotoArg {
  photo: PhotoSourceArg,
}


sig EventDetails {
  tag: String,
}


sig MissingDetails {
  source_event_fields: lone String,
}


sig EmmCreateExceptionsReportType {
  description: String,
}


sig FedAdminRole {
  tag: String,
}


sig LegalHoldsActivateAHoldType {
  description: String,
}


sig ListFolderMembersCursorArg {
  limit: Int,
  actions: set MemberAction,
}


sig SfTeamInviteDetails {
  target_asset_index: Int,
  original_folder_name: String,
  sharing_permission: lone String,
}


sig PaperFolderFollowedType {
  description: String,
}


sig GovernancePolicyDeleteType {
  description: String,
}


sig SendForSignaturePolicyChangedType {
  description: String,
}


sig IpAddress {
  // Primitive type: string
  value: String
}


sig PropertyField {
  name: String,
  value: String,
}


sig ListPaperDocsArgs {
  sort_by: ListPaperDocsSortBy,
  limit: Int,
  sort_order: ListPaperDocsSortOrder,
  filter_by: ListPaperDocsFilterBy,
}


sig GetTemplateResult {
  // Generic object with no specific type
}


sig BinderAddPageDetails {
  event_uuid: String,
  binder_item_name: String,
  doc_title: String,
}


sig DirectoryRestrictionsRemoveMembersType {
  description: String,
}


sig NamespaceRelativePathLogInfo {
  relative_path: lone FilePath,
  is_shared_namespace: lone Bool,
  ns_id: lone NamespaceId,
}


sig PaperDeploymentPolicy {
  tag: String,
}


sig PaperDocId {
  // Primitive type: string
  value: String
}


sig SharingChangeLinkAllowChangeExpirationPolicyType {
  description: String,
}


sig SetCustomQuotaArg {
  users_and_quotas: set UserCustomQuotaArg,
}


sig RelocationArg {
  // Generic object with no specific type
}


sig DeviceApprovalsRemoveExceptionDetails {
}


sig StorageBucket {
  users: Int,
  bucket: String,
}


sig SharedLinkSettingsRemoveExpirationDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
  previous_value: lone DropboxTimestamp,
}


sig TeamActivityCreateReportFailType {
  description: String,
}


sig MembersDeactivateArg {
  // Generic object with no specific type
}


sig GetTeamEventsContinueArg {
  cursor: String,
}


sig GetTeamEventsError {
  tag: String,
}


sig TeamNamespacesListContinueArg {
  cursor: String,
}


sig TeamProfileRemoveBackgroundType {
  description: String,
}


sig SfFbInviteType {
  description: String,
}


sig TfaRemoveSecurityKeyType {
  description: String,
}


sig MembersAddV2Arg {
  // Generic object with no specific type
}


sig LogoutDetails {
  login_id: lone String,
}


sig TeamFolderGetInfoItem {
  tag: String,
}


sig BinderRemoveSectionType {
  description: String,
}


sig BinderReorderSectionType {
  description: String,
}


sig SfTeamUninviteDetails {
  target_asset_index: Int,
  original_folder_name: String,
}


sig SsoChangePolicyType {
  description: String,
}


sig TeamName {
  team_display_name: String,
  team_legal_name: String,
}


sig PaperContentAddToFolderDetails {
  parent_asset_index: Int,
  target_asset_index: Int,
  event_uuid: String,
}


sig DeviceSessionArg {
  session_id: String,
  team_member_id: String,
}


sig PaperEnabledUsersGroupRemovalDetails {
}


sig ListUsersOnFolderResponse {
  invitees: set InviteeInfo,
  users: set UserInfo,
  cursor: Cursor,
  has_more: Bool,
}


sig EmmState {
  tag: String,
}


sig TeamProfileChangeDefaultLanguageType {
  description: String,
}


sig SharedLinkSettingsChangeExpirationDetails {
  shared_content_link: lone String,
  new_value: lone DropboxTimestamp,
  previous_value: lone DropboxTimestamp,
  shared_content_access_level: AccessLevel,
}


sig InviteAcceptanceEmailPolicyChangedType {
  description: String,
}


sig FileLockingPolicyState {
  tag: String,
}


sig TeamFolderPermanentlyDeleteError {
  tag: String,
}


sig ListTeamAppsArg {
  cursor: lone String,
}


sig UserInfoWithPermissionLevel {
  user: UserInfo,
  permission_level: PaperDocPermissionLevel,
}


sig LegalHoldsAddMembersDetails {
  legal_hold_id: String,
  name: String,
}


sig TeamFolderPermanentlyDeleteType {
  description: String,
}


sig TeamMergeRequestRevokedDetails {
  team: String,
}


sig TeamMergeRequestAcceptedShownToPrimaryTeamType {
  description: String,
}


sig UnshareFolderArg {
  shared_folder_id: SharedFolderId,
  leave_a_copy: Bool,
}


sig FolderAction {
  tag: String,
}


sig LegalHoldsListHeldRevisionsContinueArg {
  id: LegalHoldId,
  cursor: lone ListHeldRevisionCursor,
}


sig TeamMemberPolicies {
  suggest_members_policy: SuggestMembersPolicy,
  sharing: TeamSharingPolicies,
  emm_state: EmmState,
  office_addin: OfficeAddInPolicy,
}


sig CameraUploadsPolicyState {
  tag: String,
}


sig ClassificationCreateReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig SharedFileMetadata {
  policy: FolderPolicy,
  expected_link_metadata: lone ExpectedSharedContentLinkMetadata,
  preview_url: String,
  id: FileId,
  owner_display_names: set String,
  owner_team: lone Team,
  name: String,
  access_type: lone AccessLevel,
  path_lower: lone String,
  time_invited: lone DropboxTimestamp,
  path_display: lone String,
  link_metadata: lone SharedContentLinkMetadata,
  parent_shared_folder_id: lone SharedFolderId,
  permissions: set FilePermission,
}


sig FileRestoreType {
  description: String,
}


sig PaperDocFollowedType {
  description: String,
}


sig MemberSuggestionsChangePolicyType {
  description: String,
}


sig MicrosoftOfficeAddinChangePolicyDetails {
  new_value: MicrosoftOfficeAddinPolicy,
  previous_value: lone MicrosoftOfficeAddinPolicy,
}


sig BackupAdminInvitationSentDetails {
}


sig SharingAllowlistListArg {
  limit: Int,
}


sig ShowcaseFileAddedType {
  description: String,
}


sig SetAccessInheritanceError {
  tag: String,
}


sig NoteAclInviteOnlyType {
  description: String,
}


sig SharedFolderMembersInheritancePolicy {
  tag: String,
}


sig TeamProfileRemoveBackgroundDetails {
}


sig TfaRemoveSecurityKeyDetails {
}


sig DataPlacementRestrictionSatisfyPolicyDetails {
  placement_restriction: PlacementRestriction,
}


sig WatermarkingPolicy {
  tag: String,
}


sig TfaRemoveExceptionDetails {
}


sig ImportFormat {
  tag: String,
}


sig MemberSpaceLimitsChangePolicyDetails {
  previous_value: lone Int,
  new_value: lone Int,
}


sig AccountCaptureChangeAvailabilityDetails {
  new_value: AccountCaptureAvailability,
  previous_value: lone AccountCaptureAvailability,
}


sig RansomwareAlertCreateReportFailedType {
  description: String,
}


sig LegalHoldsListHeldRevisionsError {
  tag: String,
}


sig PaperDocEditDetails {
  event_uuid: String,
}


sig SharedLinkSettingsRemoveExpirationType {
  description: String,
}


sig ListTeamDevicesError {
  tag: String,
}


sig PaperChangePolicyType {
  description: String,
}


sig MembersRemoveArg {
  // Generic object with no specific type
}


sig ShareFolderArg {
  // Generic object with no specific type
}


sig AccessInheritance {
  tag: String,
}


sig GovernancePolicyContentDisposedType {
  description: String,
}


sig EmailIngestPolicy {
  tag: String,
}


sig ResolvedVisibility {
  tag: String,
}


sig IntegrationDisconnectedDetails {
  integration_name: String,
}


sig PaperDefaultFolderPolicy {
  tag: String,
}


sig FolderOverviewItemUnpinnedType {
  description: String,
}


sig ShowcaseUnresolveCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig SaveUrlArg {
  path: Path,
  url: String,
}


sig TeamFolderRenameDetails {
  previous_folder_name: String,
  new_folder_name: String,
}


sig ShowcaseRestoredDetails {
  event_uuid: String,
}


sig TeamMergeRequestReminderType {
  description: String,
}


sig RansomwareRestoreProcessStartedDetails {
  extension: String,
}


sig GetThumbnailBatchResult {
  entries: set GetThumbnailBatchResultEntry,
}


sig LegalHoldsReleaseAHoldType {
  description: String,
}


sig SetProfilePhotoError {
  tag: String,
}


sig TeamProfileChangeBackgroundType {
  description: String,
}


sig TeamGetInfoResult {
  team_id: String,
  num_provisioned_users: Int,
  num_licensed_users: Int,
  policies: TeamMemberPolicies,
  name: String,
  num_used_licenses: Int,
}


sig SharedContentDownloadType {
  description: String,
}


sig DevicesActive {
  total: NumberPerDay,
  windows: NumberPerDay,
  ios: NumberPerDay,
  android: NumberPerDay,
  other: NumberPerDay,
  macos: NumberPerDay,
  linux: NumberPerDay,
}


sig ObjectLabelUpdatedValueDetails {
  label_type: LabelType,
}


sig MembersAddLaunchV2Result {
  tag: String,
}


sig UserGeneratedTag {
  tag_text: TagText,
}


sig AccountCaptureChangePolicyType {
  description: String,
}


sig SfAllowNonMembersToViewSharedLinksType {
  description: String,
}


sig LegalHoldsPolicyCreateArg {
  start_date: lone DropboxTimestamp,
  name: LegalHoldPolicyName,
  members: set TeamMemberId,
  end_date: lone DropboxTimestamp,
  description: lone LegalHoldPolicyDescription,
}


sig PaperDocAddCommentType {
  description: String,
}


sig IndividualSpaceAllocation {
  allocated: Int,
}


sig TeamNamespacesListArg {
  limit: Int,
}


sig PaperCreateResult {
  file_id: FileId,
  paper_revision: Int,
  result_path: String,
  url: String,
}


sig MemberChangeAdminRoleDetails {
  new_value: lone AdminRole,
  previous_value: lone AdminRole,
}


sig AdminAlertGeneralStateEnum {
  tag: String,
}


sig AppLinkUserDetails {
  app_info: AppLogInfo,
}


sig GovernancePolicyAddFolderFailedDetails {
  folder: String,
  governance_policy_id: String,
  name: String,
  policy_type: lone PolicyType,
  reason: lone String,
}


sig PathToTags {
  path: Path,
  tags: set Tag,
}


sig RewindFolderType {
  description: String,
}


sig PaperContentAddToFolderType {
  description: String,
}


sig LegalHoldsListHeldRevisionsArg {
  id: LegalHoldId,
}


sig TeamFolderListArg {
  limit: Int,
}


sig FolderOverviewItemPinnedType {
  description: String,
}


sig FileProviderMigrationPolicyChangedType {
  description: String,
}


sig PaperDocChangeMemberRoleDetails {
  event_uuid: String,
  access_type: PaperAccessType,
}


sig ResellerSupportSessionStartDetails {
}


sig DomainVerificationAddDomainSuccessDetails {
  domain_names: set String,
  verification_method: lone String,
}


sig RemoveFolderMemberError {
  tag: String,
}


sig UpdateTemplateResult {
  template_id: TemplateId,
}


sig TeamProfileChangeNameDetails {
  previous_value: lone TeamName,
  new_value: TeamName,
}


sig GroupRemoveExternalIdType {
  description: String,
}


sig SecondaryMailsPolicy {
  tag: String,
}


sig ShowcaseRemoveMemberDetails {
  event_uuid: String,
}


sig UploadSessionStartError {
  tag: String,
}


sig ListMemberAppsResult {
  linked_api_apps: set ApiApp,
}


sig TeamEncryptionKeyEnableKeyType {
  description: String,
}


sig Path {
  // Primitive type: string
  value: String
}


sig UploadSessionType {
  tag: String,
}


sig PathOrLink {
  tag: String,
}


sig TeamSelectiveSyncPolicy {
  tag: String,
}


sig UserFeatureValue {
  tag: String,
}


sig TeamMemberInfo {
  profile: TeamMemberProfile,
  role: AdminTier,
}


sig CustomQuotaUsersArg {
  users: set UserSelectorArg,
}


sig ListFolderContinueError {
  tag: String,
}


sig SharedLinkSettingsAllowDownloadDisabledType {
  description: String,
}


sig LockFileResultEntry {
  tag: String,
}


sig GeneralFileRequestsError {
  tag: String,
}


sig MemberChangeExternalIdDetails {
  new_value: MemberExternalId,
  previous_value: MemberExternalId,
}


sig MoveIntoFamilyError {
  tag: String,
}


sig GovernancePolicyEditDurationType {
  description: String,
}


sig FileAddCommentType {
  description: String,
}


sig ThumbnailMode {
  tag: String,
}


sig TemplateId {
  // Primitive type: string
  value: String
}


sig PaperEnabledUsersGroupAdditionDetails {
}


sig AddFolderMemberError {
  tag: String,
}


sig GroupFullInfo {
  // Generic object with no specific type
}


sig FileRequestReceiveFileType {
  description: String,
}


sig SfFbInviteDetails {
  sharing_permission: lone String,
  original_folder_name: String,
  target_asset_index: Int,
}


sig GetTeamEventsArg {
  account_id: lone AccountId,
  time: lone TimeRange,
  category: lone EventCategory,
  limit: Int,
  event_type: lone EventTypeArg,
}


sig AccessLevel {
  tag: String,
}


sig SharedContentAddInviteesType {
  description: String,
}


sig UserTagsRemovedType {
  description: String,
}


sig GetMetadataError {
  tag: String,
}


sig SearchV2Cursor {
  // Primitive type: string
  value: String
}


sig MemberSelector {
  tag: String,
}


sig GroupsListContinueArg {
  cursor: String,
}


sig TeamFolderActivateError {
  tag: String,
}


sig CountFileRequestsResult {
  file_request_count: Int,
}


sig SharedContentChangeInviteeRoleDetails {
  previous_access_level: lone AccessLevel,
  new_access_level: AccessLevel,
  invitee: EmailAddress,
}


sig InsufficientPlan {
  upsell_url: lone String,
  message: String,
}


sig SmarterSmartSyncPolicyChangedDetails {
  previous_value: SmarterSmartSyncPolicyState,
  new_value: SmarterSmartSyncPolicyState,
}


sig FileTransfersFileAddDetails {
  file_transfer_id: String,
}


sig Cursor {
  value: String,
  expiration: lone DropboxTimestamp,
}


sig FileRevertDetails {
}


sig SharedFolderMemberPolicy {
  tag: String,
}


sig DeleteBatchResult {
  // Generic object with no specific type
}


sig InvalidPropertyGroupError {
  tag: String,
}


sig SfTeamGrantAccessDetails {
  target_asset_index: Int,
  original_folder_name: String,
}


sig SharedLinkChangeVisibilityDetails {
  previous_value: lone SharedLinkVisibility,
  new_value: SharedLinkVisibility,
}


sig TeamReportFailureReason {
  tag: String,
}


sig ObjectLabelRemovedDetails {
  label_type: LabelType,
}


sig ClassificationType {
  tag: String,
}


sig SharedLinkAddExpiryType {
  description: String,
}


sig DeleteFileRequestError {
  tag: String,
}


sig ListUsersCursorError {
  tag: String,
}


sig MetadataV2 {
  tag: String,
}


sig MembersSetProfileError {
  tag: String,
}


sig TeamFolderUpdateSyncSettingsError {
  tag: String,
}


sig RelocationBatchErrorEntry {
  tag: String,
}


sig ListFileMembersIndividualResult {
  tag: String,
}


sig TeamExtensionsPolicyChangedDetails {
  new_value: TeamExtensionsPolicy,
  previous_value: TeamExtensionsPolicy,
}


sig SfTeamInviteType {
  description: String,
}


sig SharePathError {
  tag: String,
}


sig ExtendedVersionHistoryChangePolicyType {
  description: String,
}


sig MembersListContinueArg {
  cursor: String,
}


sig RevokeLinkedAppStatus {
  error_type: lone RevokeLinkedAppError,
  success: Bool,
}


sig FileId {
  // Primitive type: string
  value: String
}


sig FileEditDetails {
}


sig RelinquishFileMembershipArg {
  file: PathOrId,
}


sig WritePathOrId {
  // Primitive type: string
  value: String
}


sig TeamMergeRequestAcceptedShownToSecondaryTeamDetails {
  primary_team: String,
  sent_by: String,
}


sig InvalidAccountTypeError {
  tag: String,
}


sig DropboxTimestamp {
  // Primitive type: string
  value: String
}


sig TeamActivityCreateReportType {
  description: String,
}


sig RevokeDeviceSessionBatchError {
  tag: String,
}


sig ExternalSharingReportFailedType {
  description: String,
}


sig SharedContentAddLinkExpiryType {
  description: String,
}


sig ShowcaseCreatedType {
  description: String,
}


sig TeamSharingWhitelistSubjectsChangedType {
  description: String,
}


sig NoteAclLinkDetails {
}


sig TeamSelectiveSyncSettingsChangedDetails {
  new_value: SyncSetting,
  previous_value: SyncSetting,
}


sig AccountCaptureNotificationEmailsSentDetails {
  domain_name: String,
  notification_type: lone AccountCaptureNotificationType,
}


sig GoogleSsoChangePolicyDetails {
  new_value: GoogleSsoPolicy,
  previous_value: lone GoogleSsoPolicy,
}


sig RelocationBatchError {
  tag: String,
}


sig FolderLinkRestrictionPolicyChangedType {
  description: String,
}


sig SharedFolderJoinPolicy {
  tag: String,
}


sig TeamExtensionsPolicy {
  tag: String,
}


sig LegalHoldsPolicyUpdateError {
  tag: String,
}


sig AddFolderMemberArg {
  members: set AddMember,
  shared_folder_id: SharedFolderId,
  quiet: Bool,
  custom_message: lone String,
}


sig ExportMembersReportFailDetails {
  failure_reason: TeamReportFailureReason,
}


sig DocLookupError {
  tag: String,
}


sig UploadError {
  tag: String,
}


sig WriteMode {
  tag: String,
}


sig FileEditType {
  description: String,
}


sig TeamFolderTeamSharedDropboxError {
  tag: String,
}


sig TfaAddBackupPhoneType {
  description: String,
}


sig SharingPolicy {
  public_sharing_policy: lone SharingPublicPolicyType,
  team_sharing_policy: lone SharingTeamPolicyType,
}


sig AlertRecipientsSettingType {
  tag: String,
}


sig MemberExternalId {
  // Primitive type: string
  value: String
}


sig TeamMergeRequestCanceledShownToPrimaryTeamType {
  description: String,
}


sig ListSharedLinksArg {
  cursor: lone String,
  path: lone ReadPath,
  direct_only: lone Bool,
}


sig UserAddResult {
  tag: String,
}


sig ThumbnailSize {
  tag: String,
}


sig GroupChangeMemberRoleType {
  description: String,
}


sig DownloadArg {
  rev: lone Rev,
  path: ReadPath,
}


sig MembersTransferFilesError {
  tag: String,
}


sig DeleteArg {
  path: WritePathOrId,
  parent_rev: lone Rev,
}


sig PasswordResetAllDetails {
}


sig MemberDeleteProfilePhotoType {
  description: String,
}


sig NoPasswordLinkGenCreateReportDetails {
  start_date: DropboxTimestamp,
  end_date: DropboxTimestamp,
}


sig IncludeMembersArg {
  return_members: Bool,
}


sig UserTagsAddedType {
  description: String,
}


sig TeamFolderArchiveLaunch {
  tag: String,
}


sig TeamMergeRequestCanceledExtraDetails {
  tag: String,
}


sig ListDocsCursorError {
  tag: String,
}


sig GroupCreateDetails {
  is_company_managed: lone Bool,
  join_policy: lone GroupJoinPolicy,
}


sig RemovePropertiesArg {
  path: PathOrId,
  property_template_ids: set TemplateId,
}


sig TeamFolderAccessError {
  tag: String,
}


sig SecondaryEmailDeletedDetails {
  secondary_email: EmailAddress,
}


sig CountFileRequestsError {
  tag: String,
}


sig GroupUserManagementChangePolicyDetails {
  new_value: GroupCreation,
  previous_value: lone GroupCreation,
}


sig MemberSuggestionsChangePolicyDetails {
  new_value: MemberSuggestionsPolicy,
  previous_value: lone MemberSuggestionsPolicy,
}


sig AdminAlertingAlertConfiguration {
  sensitivity_level: lone AdminAlertingAlertSensitivity,
  excluded_file_extensions: lone String,
  alert_state: lone AdminAlertingAlertStatePolicy,
  recipients_settings: lone RecipientsConfiguration,
  text: lone String,
}


sig ShowcaseChangeExternalSharingPolicyType {
  description: String,
}


sig MembersGetInfoItem {
  tag: String,
}


sig CollectionShareDetails {
  album_name: String,
}


sig ResellerRole {
  tag: String,
}


sig GroupUserManagementChangePolicyType {
  description: String,
}


sig OptionalNamePart {
  // Primitive type: string
  value: String
}


sig ModifySharedLinkSettingsArgs {
  remove_expiration: Bool,
  settings: SharedLinkSettings,
  url: String,
}


sig MemberSetProfilePhotoType {
  description: String,
}


sig LegalHoldsExportDownloadedDetails {
  part: lone String,
  name: String,
  export_name: String,
  legal_hold_id: String,
  file_name: lone String,
}


sig OfficeAddInPolicy {
  tag: String,
}


sig DeleteBatchLaunch {
  tag: String,
}


sig PathROrId {
  // Primitive type: string
  value: String
}


sig PaperContentRestoreType {
  description: String,
}


sig SharedContentRestoreInviteesDetails {
  invitees: set EmailAddress,
  shared_content_access_level: AccessLevel,
}


sig SharedFolderChangeMembersInheritancePolicyType {
  description: String,
}


sig FileTransfersPolicyChangedDetails {
  new_value: FileTransfersPolicy,
  previous_value: FileTransfersPolicy,
}


sig WebSessionsChangeIdleLengthPolicyType {
  description: String,
}


sig QuickActionType {
  tag: String,
}


sig PaperMemberPolicy {
  tag: String,
}


sig TeamMemberInfoV2Result {
  member_info: TeamMemberInfoV2,
}


sig TeamInviteDetails {
  invite_method: InviteMethod,
  additional_license_purchase: lone Bool,
}


sig HasTeamSelectiveSyncValue {
  tag: String,
}


sig ShowcaseFileDownloadType {
  description: String,
}


sig EmmCreateExceptionsReportDetails {
}


sig PaperContentError {
  tag: String,
}


sig UpdateFileRequestError {
  tag: String,
}


sig DeviceApprovalsChangeMobilePolicyDetails {
  previous_value: lone DeviceApprovalsPolicy,
  new_value: lone DeviceApprovalsPolicy,
}


sig AddSecondaryEmailsResult {
  results: set UserAddResult,
}


sig PaperDocRequestAccessType {
  description: String,
}


sig DeleteManualContactsError {
  tag: String,
}


sig SharingAllowlistListResponse {
  emails: set String,
  has_more: Bool,
  domains: set String,
  cursor: String,
}


sig DomainInvitesDeclineRequestToJoinTeamType {
  description: String,
}


sig MemberSpaceLimitsChangeCustomQuotaDetails {
  previous_value: Int,
  new_value: Int,
}


sig WebSessionsChangeFixedLengthPolicyType {
  description: String,
}


sig FileUnlikeCommentDetails {
  comment_text: lone String,
}


sig ExcludedUsersListContinueArg {
  cursor: String,
}


sig FileTransfersTransferDeleteDetails {
  file_transfer_id: String,
}


sig DeleteFileRequestsResult {
  file_requests: set FileRequest,
}


sig SmartSyncOptOutDetails {
  previous_value: SmartSyncOptOutPolicy,
  new_value: SmartSyncOptOutPolicy,
}


sig GeoLocationLogInfo {
  city: lone String,
  region: lone String,
  ip_address: IpAddress,
  country: lone String,
}


sig UserFeaturesGetValuesBatchError {
  tag: String,
}


sig PaperPublishedLinkViewDetails {
  event_uuid: String,
}


sig GroupManagementType {
  tag: String,
}


sig PasswordResetDetails {
}


sig ParentFolderAccessInfo {
  shared_folder_id: SharedFolderId,
  folder_name: String,
  permissions: set MemberPermission,
  path: String,
}


sig PasswordStrengthPolicy {
  tag: String,
}


sig Sha256HexHash {
  // Primitive type: string
  value: String
}


sig SharedLinkChangeExpiryDetails {
  new_value: lone DropboxTimestamp,
  previous_value: lone DropboxTimestamp,
}


sig RewindPolicyChangedType {
  description: String,
}


sig PaperDocCreateError {
  tag: String,
}


sig SfExternalInviteWarnDetails {
  new_sharing_permission: lone String,
  original_folder_name: String,
  previous_sharing_permission: lone String,
  target_asset_index: Int,
}


sig ExportMembersReportType {
  description: String,
}


sig PaperContentAddMemberType {
  description: String,
}


sig SharedContentChangeDownloadsPolicyType {
  description: String,
}


sig GovernancePolicyExportRemovedDetails {
  name: String,
  policy_type: lone PolicyType,
  governance_policy_id: String,
  export_name: String,
}


sig MemberAddArgBase {
  is_directory_restricted: lone Bool,
  member_external_id: lone MemberExternalId,
  member_email: EmailAddress,
  member_surname: lone OptionalNamePart,
  send_welcome_email: Bool,
  member_given_name: lone OptionalNamePart,
  member_persistent_id: lone String,
}


sig SharedFileMembers {
  cursor: lone String,
  invitees: set InviteeMembershipInfo,
  users: set UserFileMembershipInfo,
  groups: set GroupMembershipInfo,
}


sig FileRequestDetails {
  deadline: lone FileRequestDeadline,
  asset_index: Int,
}


sig UserOrTeamLinkedAppLogInfo {
  // Generic object with no specific type
}


sig CameraUploadsPolicyChangedDetails {
  new_value: CameraUploadsPolicy,
  previous_value: CameraUploadsPolicy,
}


sig TeamEncryptionKeyCreateKeyType {
  description: String,
}


sig DomainInvitesSetInviteNewUserPrefToNoDetails {
}


sig MembersSetProfileArg {
  new_is_directory_restricted: lone Bool,
  new_external_id: lone MemberExternalId,
  user: UserSelectorArg,
  new_given_name: lone OptionalNamePart,
  new_email: lone EmailAddress,
  new_persistent_id: lone String,
  new_surname: lone OptionalNamePart,
}


sig GroupAddMemberDetails {
  is_group_owner: Bool,
}


sig SharedContentAddLinkExpiryDetails {
  new_value: lone DropboxTimestamp,
}


sig PaperDocChangeSubscriptionDetails {
  new_subscription_level: String,
  previous_subscription_level: lone String,
  event_uuid: String,
}


sig FolderLinkMetadata {
  // Generic object with no specific type
}


sig EmailIngestReceiveFileDetails {
  from_email: lone EmailAddress,
  inbox_name: String,
  subject: lone String,
  from_name: lone DisplayNameLegacy,
  attachment_names: set String,
}


sig ListMembersDevicesArg {
  include_mobile_clients: Bool,
  include_web_sessions: Bool,
  include_desktop_clients: Bool,
  cursor: lone String,
}


sig TeamMergeRequestExpiredShownToSecondaryTeamType {
  description: String,
}


sig DeleteFileRequestArgs {
  ids: set FileRequestId,
}


sig FileMemberRemoveActionResult {
  tag: String,
}


sig WatermarkingPolicyChangedType {
  description: String,
}


sig DomainInvitesDeclineRequestToJoinTeamDetails {
}


sig ShowcaseTrashedDeprecatedType {
  description: String,
}


sig SharedLinkSettingsRemovePasswordDetails {
  shared_content_link: lone String,
  shared_content_access_level: AccessLevel,
}


sig ListUsersOnFolderContinueArgs {
  // Generic object with no specific type
}


sig FolderSharingInfo {
  // Generic object with no specific type
}


sig CreateFolderBatchError {
  tag: String,
}


sig ShowcasePostCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig TeamExtensionsPolicyChangedType {
  description: String,
}


sig TeamEvent {
  event_type: EventType,
  context: lone ContextLogInfo,
  timestamp: DropboxTimestamp,
  involve_non_team_member: lone Bool,
  participants: set ParticipantLogInfo,
  assets: set AssetLogInfo,
  details: EventDetails,
  event_category: EventCategory,
  actor: lone ActorLogInfo,
  origin: lone OriginLogInfo,
}


sig SpaceCapsType {
  tag: String,
}


sig FileRequestsChangePolicyType {
  description: String,
}


sig SecondaryTeamRequestReminderDetails {
  sent_to: String,
}


sig PathOrId {
  // Primitive type: string
  value: String
}


sig PropertyGroup {
  template_id: TemplateId,
  fields: set PropertyField,
}


sig LogicalOperator {
  tag: String,
}


sig AppPermissionsChangedType {
  description: String,
}


sig SmarterSmartSyncPolicyChangedType {
  description: String,
}


sig DocSubscriptionLevel {
  tag: String,
}


sig SharedContentAddInviteesDetails {
  shared_content_access_level: AccessLevel,
  invitees: set EmailAddress,
}


sig FileRequestsEmailsEnabledDetails {
}


sig MembersListResult {
  cursor: String,
  members: set TeamMemberInfo,
  has_more: Bool,
}


sig SharedContentChangeLinkExpiryDetails {
  new_value: lone DropboxTimestamp,
  previous_value: lone DropboxTimestamp,
}


sig OriginLogInfo {
  geo_location: lone GeoLocationLogInfo,
  access_method: AccessMethodLogInfo,
}


sig RansomwareAlertCreateReportDetails {
}


sig EmmCreateUsageReportType {
  description: String,
}


sig BinderReorderSectionDetails {
  event_uuid: String,
  binder_item_name: String,
  doc_title: String,
}


sig PaperChangeMemberLinkPolicyType {
  description: String,
}


sig PaperContentPermanentlyDeleteDetails {
  event_uuid: String,
}


sig TeamFolderCreateType {
  description: String,
}


sig FileResolveCommentDetails {
  comment_text: lone String,
}


sig TeamMergeRequestAcceptedType {
  description: String,
}


sig RemoveCustomQuotaResult {
  tag: String,
}


sig ShowcaseTrashedDetails {
  event_uuid: String,
}


sig SfFbUninviteType {
  description: String,
}


sig GroupCreation {
  tag: String,
}


sig ShmodelEnableDownloadsDetails {
  shared_link_owner: lone UserLogInfo,
}


sig SharedLinkDownloadType {
  description: String,
}


sig GroupChangeExternalIdDetails {
  previous_value: GroupExternalId,
  new_value: GroupExternalId,
}


sig MemberAddNameDetails {
  new_value: UserNameLogInfo,
}


sig AlphaResolvedVisibility {
  tag: String,
}


sig AccountCaptureMigrateAccountType {
  description: String,
}


sig FileTransfersTransferDownloadDetails {
  file_transfer_id: String,
}


sig FolderPolicy {
  acl_update_policy: AclUpdatePolicy,
  shared_link_policy: SharedLinkPolicy,
  member_policy: lone MemberPolicy,
  resolved_member_policy: lone MemberPolicy,
  viewer_info_policy: lone ViewerInfoPolicy,
}


sig FileLockingValue {
  tag: String,
}


sig RansomwareRestoreProcessCompletedType {
  description: String,
}


sig MembersGetInfoItemBase {
  tag: String,
}


sig ListFileRequestsError {
  tag: String,
}


sig ObjectLabelAddedDetails {
  label_type: LabelType,
}


sig DeviceChangeIpWebType {
  description: String,
}


sig MembersSuspendError {
  tag: String,
}


sig UserTagsAddedDetails {
  values: set String,
}


sig DataPlacementRestrictionSatisfyPolicyType {
  description: String,
}


sig DataResidencyMigrationRequestUnsuccessfulDetails {
}


sig LegalHoldPolicyName {
  // Primitive type: string
  value: String
}


sig LegalHoldsListHeldRevisionsContinueError {
  tag: String,
}


sig ResellerSupportChangePolicyType {
  description: String,
}


sig MembersGetInfoResult {
  items: set MembersGetInfoItem
}


sig BackupInvitationOpenedDetails {
}


sig TeamLogInfo {
  display_name: String,
}


sig FeatureValue {
  tag: String,
}


sig ListTemplateResult {
  template_ids: set TemplateId,
}


sig TeamEncryptionKeyCreateKeyDetails {
}


sig SharedLinkSettingsAddPasswordType {
  description: String,
}


sig PaperDefaultFolderPolicyChangedType {
  description: String,
}


sig SharedContentCopyType {
  description: String,
}


sig LegalHoldsListHeldRevisionResult {
  entries: set LegalHoldHeldRevisionMetadata,
  cursor: lone ListHeldRevisionCursor,
  has_more: Bool,
}


sig RansomwareRestoreProcessCompletedDetails {
  status: String,
  restored_files_count: Int,
  restored_files_failed_count: Int,
}


sig ShowcaseEditedDetails {
  event_uuid: String,
}


sig ShmodelGroupShareType {
  description: String,
}


sig TeamMergeRequestRejectedShownToSecondaryTeamDetails {
  sent_by: String,
}


sig GroupRemoveMemberType {
  description: String,
}


sig NoteSharedType {
  description: String,
}


sig TeamFolderListResult {
  team_folders: set TeamFolderMetadata,
  has_more: Bool,
  cursor: String,
}


sig GuestAdminSignedOutViaTrustedTeamsType {
  description: String,
}


sig FullTeam {
  // Generic object with no specific type
}


sig GroupMemberInfo {
  access_type: GroupAccessType,
  profile: MemberProfile,
}


sig MembersInfo {
  team_member_ids: set TeamMemberId,
  permanently_deleted_users: Int,
}


sig PaperDocViewType {
  description: String,
}


sig EmmErrorDetails {
  error_details: FailureDetailsLogInfo,
}


sig SharedLinkSettingsAddPasswordDetails {
  shared_content_access_level: AccessLevel,
  shared_content_link: lone String,
}


sig ExtendedVersionHistoryChangePolicyDetails {
  new_value: ExtendedVersionHistoryPolicy,
  previous_value: lone ExtendedVersionHistoryPolicy,
}


sig UnmountFolderArg {
  shared_folder_id: SharedFolderId,
}


sig AddFileMemberError {
  tag: String,
}


sig ListFileRequestsArg {
  limit: Int,
}


sig UploadSessionStartBatchResult {
  session_ids: set String,
}


sig MemberAction {
  tag: String,
}


sig ExternalDriveBackupEligibilityStatusCheckedType {
  description: String,
}


sig PaperChangeMemberPolicyDetails {
  previous_value: lone PaperMemberPolicy,
  new_value: PaperMemberPolicy,
}


sig GroupSelectorWithTeamGroupError {
  tag: String,
}


sig TeamMergeRequestExpiredShownToPrimaryTeamDetails {
  secondary_team: String,
  sent_by: String,
}


sig AlphaGetMetadataError {
  tag: String,
}


sig EnabledDomainInvitesType {
  description: String,
}


sig PaperAccessError {
  tag: String,
}


sig EmailAddress {
  // Primitive type: string
  value: String
}


sig MembersListArg {
  limit: Int,
  include_removed: Bool,
}


sig FileAddCommentDetails {
  comment_text: lone String,
}


sig TeamEncryptionKeyRotateKeyType {
  description: String,
}


sig SharedContentChangeLinkPasswordType {
  description: String,
}


sig FileDeleteCommentType {
  description: String,
}


sig ShareFolderError {
  tag: String,
}


sig ComputerBackupPolicy {
  tag: String,
}


sig ShowcaseAddMemberType {
  description: String,
}


sig LegalHoldHeldRevisionMetadata {
  original_revision_id: Rev,
  file_type: String,
  size: Int,
  original_file_path: Path,
  new_filename: String,
  server_modified: DropboxTimestamp,
  author_member_status: TeamMemberStatus,
  author_member_id: TeamMemberId,
  content_hash: Sha256HexHash,
  author_email: EmailAddress,
}


sig SharedFolderNestType {
  description: String,
}


sig InviteAcceptanceEmailPolicyChangedDetails {
  previous_value: InviteAcceptanceEmailPolicy,
  new_value: InviteAcceptanceEmailPolicy,
}


sig FileRequestDeleteDetails {
  file_request_id: lone FileRequestId,
  previous_details: lone FileRequestDetails,
}


sig MembersGetAvailableTeamMemberRolesResult {
  roles: set TeamMemberRole,
}


sig SignInAsSessionStartType {
  description: String,
}


sig EmmRemoveExceptionType {
  description: String,
}


sig SharedContentRestoreMemberDetails {
  shared_content_access_level: AccessLevel,
}


sig FileRollbackChangesType {
  description: String,
}


sig TeamMergeRequestRejectedShownToSecondaryTeamType {
  description: String,
}


sig PaperDownloadFormat {
  tag: String,
}


sig FileLikeCommentDetails {
  comment_text: lone String,
}


sig SyncSetting {
  tag: String,
}


sig GroupAddMemberType {
  description: String,
}


sig SharingUserError {
  tag: String,
}


sig RefPaperDoc {
  doc_id: PaperDocId,
}


sig TfaRemoveBackupPhoneType {
  description: String,
}


sig LegalHoldsReleaseAHoldDetails {
  legal_hold_id: String,
  name: String,
}


sig UploadSessionFinishBatchLaunch {
  tag: String,
}


sig DurationLogInfo {
  amount: Int,
  unit: TimeUnit,
}


sig AccountLockOrUnlockedType {
  description: String,
}


sig UserFeaturesGetValuesBatchArg {
  features: set UserFeature,
}


sig DeviceApprovalsChangeUnlinkActionDetails {
  previous_value: lone DeviceUnlinkPolicy,
  new_value: lone DeviceUnlinkPolicy,
}


sig DeviceSyncBackupStatusChangedType {
  description: String,
}


sig MemberSpaceLimitsAddCustomQuotaDetails {
  new_value: Int,
}


sig ShowcaseRestoredType {
  description: String,
}


sig GuestAdminSignedInViaTrustedTeamsType {
  description: String,
}


sig DeviceLinkFailDetails {
  device_type: DeviceType,
  ip_address: lone IpAddress,
}


sig SharedNoteOpenedDetails {
}


sig GovernancePolicyAddFolderFailedType {
  description: String,
}


sig SecondaryEmailDeletedType {
  description: String,
}


sig PathRoot {
  tag: String,
}


sig PaperDocResolveCommentDetails {
  comment_text: lone String,
  event_uuid: String,
}


sig RevokeDeviceSessionError {
  tag: String,
}


sig LegalHoldsPolicyCreateResult {
  // Generic object with no specific type
}


sig ListFilesArg {
  limit: Int,
  actions: set FileAction,
}


sig GroupMembersAddError {
  tag: String,
}


sig BaseTeamFolderError {
  tag: String,
}


sig MemberPermanentlyDeleteAccountContentsDetails {
}


sig DeviceType {
  tag: String,
}


sig NoPasswordLinkGenCreateReportType {
  description: String,
}


sig LegalHoldsExportCancelledDetails {
  name: String,
  export_name: String,
  legal_hold_id: String,
}


sig SessionId {
  // Primitive type: string
  value: String
}


sig RevokeLinkedApiAppBatchArg {
  revoke_linked_app: set RevokeLinkedApiAppArg,
}


sig SfTeamJoinFromOobLinkDetails {
  target_asset_index: Int,
  original_folder_name: String,
  sharing_permission: lone String,
  token_key: lone String,
}


sig AddSecondaryEmailsArg {
  new_secondary_emails: set UserSecondaryEmailsArg,
}


sig FileRestoreDetails {
}


sig AccountCaptureAvailability {
  tag: String,
}


sig IntegrationPolicyChangedDetails {
  previous_value: IntegrationPolicy,
  new_value: IntegrationPolicy,
  integration_name: String,
}


sig UserSelectorError {
  tag: String,
}


sig TeamFolderRenameError {
  tag: String,
}


sig LegalHoldsExportAHoldDetails {
  name: String,
  legal_hold_id: String,
  export_name: lone String,
}


sig FilePreviewDetails {
}


sig PaperDocEditCommentType {
  description: String,
}


sig FileRequestsPolicy {
  tag: String,
}


sig ShowcaseChangeExternalSharingPolicyDetails {
  previous_value: ShowcaseExternalSharingPolicy,
  new_value: ShowcaseExternalSharingPolicy,
}


sig MembersSetProfilePhotoError {
  tag: String,
}


sig PaperDocChangeSharingPolicyType {
  description: String,
}


sig TeamProfileChangeLogoDetails {
}


sig LegalHoldsListPoliciesError {
  tag: String,
}


sig BinderReorderPageType {
  description: String,
}


sig LinkedDeviceLogInfo {
  tag: String,
}


sig PaperDocDeletedDetails {
  event_uuid: String,
}


sig ThumbnailArg {
  format: ThumbnailFormat,
  path: ReadPath,
  size: ThumbnailSize,
  mode: ThumbnailMode,
}


sig PropertiesSearchCursor {
  // Primitive type: string
  value: String
}


sig ShowcaseChangeDownloadPolicyDetails {
  previous_value: ShowcaseDownloadPolicy,
  new_value: ShowcaseDownloadPolicy,
}


sig DomainVerificationAddDomainSuccessType {
  description: String,
}


sig SharedContentCopyDetails {
  shared_content_access_level: AccessLevel,
  shared_content_owner: lone UserLogInfo,
  destination_path: FilePath,
  shared_content_link: String,
}


sig PaperFolderLogInfo {
  folder_name: String,
  folder_id: String,
}


sig UpdateTemplateArg {
  description: lone String,
  template_id: TemplateId,
  add_fields: set PropertyFieldTemplate,
  name: lone String,
}


sig MemberAddExternalIdType {
  description: String,
}


sig SharingAllowlistAddResponse {
}


sig MembersGetInfoError {
  tag: String,
}


sig TokenFromOAuth1Arg {
  oauth1_token_secret: String,
  oauth1_token: String,
}


sig GroupCreateType {
  description: String,
}


sig RevokeSharedLinkArg {
  url: String,
}


sig GetCopyReferenceArg {
  path: ReadPath,
}


sig FileRequestDeleteType {
  description: String,
}


sig SharedNoteOpenedType {
  description: String,
}


sig TeamProfileAddBackgroundType {
  description: String,
}


sig LinkAudienceDisallowedReason {
  tag: String,
}


sig Route {
  auth: String,
  select_admin_mode: lone String,
  host: String,
  style: String,
  is_preview: Bool,
  is_cloud_doc_auth: Bool,
  allow_app_folder_app: Bool,
  scope: lone String,
}


sig AdminAlertingAlertStateChangedDetails {
  previous_value: AdminAlertGeneralStateEnum,
  alert_instance_id: String,
  alert_severity: AdminAlertSeverityEnum,
  alert_name: String,
  new_value: AdminAlertGeneralStateEnum,
  alert_category: AdminAlertCategoryEnum,
}


sig FolderOverviewItemPinnedDetails {
  pinned_items_asset_indices: set Int,
  folder_overview_location_asset: Int,
}


sig ExternalDriveBackupPolicyChangedDetails {
  previous_value: ExternalDriveBackupPolicy,
  new_value: ExternalDriveBackupPolicy,
}


sig DeviceManagementDisabledType {
  description: String,
}


sig AccountCaptureRelinquishAccountDetails {
  domain_name: String,
}


sig GuestAdminChangeStatusType {
  description: String,
}


sig FileTransfersTransferSendType {
  description: String,
}


sig PreviewArg {
  path: ReadPath,
  rev: lone Rev,
}


sig LegalHoldsReportAHoldDetails {
  legal_hold_id: String,
  name: String,
}


sig UserResendResult {
  tag: String,
}


sig TeamMergeRequestAcceptedExtraDetails {
  tag: String,
}


sig DomainVerificationRemoveDomainType {
  description: String,
}


sig FileTransfersTransferViewDetails {
  file_transfer_id: String,
}


sig MemberSuggestType {
  description: String,
}


sig GetAccountError {
  tag: String,
}


sig UserSelectorArg {
  tag: String,
}


sig SharedContentChangeViewerInfoPolicyDetails {
  previous_value: lone ViewerInfoPolicy,
  new_value: ViewerInfoPolicy,
}


sig PaperDocSlackShareDetails {
  event_uuid: String,
}


// API operations
// Operation: POST /team/legal_holds/list_held_revisions_continue
// Continue listing the file metadata that's under the hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_list_held_revisions_continue extends Operation {}

fact Operation_legal_holds_list_held_revisions_continue_FieldValues {
  Operation_legal_holds_list_held_revisions_continue.id = "legal_holds/list_held_revisions_continue"
  Operation_legal_holds_list_held_revisions_continue.path = "/team/legal_holds/list_held_revisions_continue"
  Operation_legal_holds_list_held_revisions_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_list_held_revisions_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_list_held_revisions_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_list_held_revisions_continue.responses
}


// Operation: POST /sharing/get_shared_link_file
// Download the shared link's file from a user's Dropbox. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_shared_link_file extends Operation {}

fact Operation_get_shared_link_file_FieldValues {
  Operation_get_shared_link_file.id = "get_shared_link_file"
  Operation_get_shared_link_file.path = "/sharing/get_shared_link_file"
  Operation_get_shared_link_file.method = "POST"
  // This operation has no request body
  no Operation_get_shared_link_file.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_shared_link_file.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_shared_link_file.responses
}


// Operation: POST /team/member_space_limits/excluded_users/remove
// Remove users from member space limits excluded users list.
one sig Operation_member_space_limits_excluded_users_remove extends Operation {}

fact Operation_member_space_limits_excluded_users_remove_FieldValues {
  Operation_member_space_limits_excluded_users_remove.id = "member_space_limits/excluded_users/remove"
  Operation_member_space_limits_excluded_users_remove.path = "/team/member_space_limits/excluded_users/remove"
  Operation_member_space_limits_excluded_users_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_excluded_users_remove.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_excluded_users_remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_excluded_users_remove.responses
}


// Operation: POST /team/get_info
// Retrieves information about a team.
one sig Operation_get_info extends Operation {}

fact Operation_get_info_FieldValues {
  Operation_get_info.id = "get_info"
  Operation_get_info.path = "/team/get_info"
  Operation_get_info.method = "POST"
  // This operation has no request body
  no Operation_get_info.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_info.responses
}


// Operation: POST /files/paper/update
// 
//     Updates an existing Paper doc with the provided content.
//      Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_paper_update extends Operation {}

fact Operation_paper_update_FieldValues {
  Operation_paper_update.id = "paper/update"
  Operation_paper_update.path = "/files/paper/update"
  Operation_paper_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_paper_update.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_paper_update.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_paper_update.responses
}


// Operation: POST /team/linked_apps/revoke_linked_app_batch
// Revoke a list of linked applications of the team members.
one sig Operation_linked_apps_revoke_linked_app_batch extends Operation {}

fact Operation_linked_apps_revoke_linked_app_batch_FieldValues {
  Operation_linked_apps_revoke_linked_app_batch.id = "linked_apps/revoke_linked_app_batch"
  Operation_linked_apps_revoke_linked_app_batch.path = "/team/linked_apps/revoke_linked_app_batch"
  Operation_linked_apps_revoke_linked_app_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_linked_apps_revoke_linked_app_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps_revoke_linked_app_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps_revoke_linked_app_batch.responses
}


// Operation: POST /sharing/check_share_job_status
// Returns the status of an asynchronous job for sharing a folder.
one sig Operation_check_share_job_status extends Operation {}

fact Operation_check_share_job_status_FieldValues {
  Operation_check_share_job_status.id = "check_share_job_status"
  Operation_check_share_job_status.path = "/sharing/check_share_job_status"
  Operation_check_share_job_status.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_check_share_job_status.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_share_job_status.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_share_job_status.responses
}


// Operation: POST /files/copy_batch/check:2
// Returns the status of an asynchronous job for :route:`copy_batch:1`. If
//     success, it returns list of results for each entry.
one sig Operation_copy_batch_check_2 extends Operation {}

fact Operation_copy_batch_check_2_FieldValues {
  Operation_copy_batch_check_2.id = "copy_batch/check:2"
  Operation_copy_batch_check_2.path = "/files/copy_batch/check:2"
  Operation_copy_batch_check_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_copy_batch_check_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_batch_check_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_batch_check_2.responses
}


// Operation: POST /file_requests/list:2
// Returns a list of file requests owned by this user. For apps with the app
//     folder permission, this will only return file requests with destinations in
//     the app folder.
one sig Operation_list_2 extends Operation {}

fact Operation_list_2_FieldValues {
  Operation_list_2.id = "list:2"
  Operation_list_2.path = "/file_requests/list:2"
  Operation_list_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_2.responses
}


// Operation: POST /team/members/add/job_status/get:2
// Once an async_job_id is returned from :route:`members/add:2` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members_add_job_status_get_2 extends Operation {}

fact Operation_members_add_job_status_get_2_FieldValues {
  Operation_members_add_job_status_get_2.id = "members/add/job_status/get:2"
  Operation_members_add_job_status_get_2.path = "/team/members/add/job_status/get:2"
  Operation_members_add_job_status_get_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_add_job_status_get_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_add_job_status_get_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_add_job_status_get_2.responses
}


// Operation: POST /team/member_space_limits/remove_custom_quota
// Remove users custom quota.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits_remove_custom_quota extends Operation {}

fact Operation_member_space_limits_remove_custom_quota_FieldValues {
  Operation_member_space_limits_remove_custom_quota.id = "member_space_limits/remove_custom_quota"
  Operation_member_space_limits_remove_custom_quota.path = "/team/member_space_limits/remove_custom_quota"
  Operation_member_space_limits_remove_custom_quota.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_remove_custom_quota.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_remove_custom_quota.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_remove_custom_quota.responses
}


// Operation: POST /files/move_batch:2
// Move multiple files or folders to different locations at once in the
//     user's Dropbox.
// 
//     This route will return job ID immediately and do the async moving job in
//     background. Please use :route:`move_batch/check:1` to check the job status.
one sig Operation_move_batch_2 extends Operation {}

fact Operation_move_batch_2_FieldValues {
  Operation_move_batch_2.id = "move_batch:2"
  Operation_move_batch_2.path = "/files/move_batch:2"
  Operation_move_batch_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_move_batch_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move_batch_2.responses
}


// Operation: POST /team/members/set_profile
// Updates a team member's profile.
// 
//     Permission : Team member management.
one sig Operation_members_set_profile extends Operation {}

fact Operation_members_set_profile_FieldValues {
  Operation_members_set_profile.id = "members/set_profile"
  Operation_members_set_profile.path = "/team/members/set_profile"
  Operation_members_set_profile.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_profile.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_profile.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_profile.responses
}


// Operation: POST /paper/docs/update
// Updates an existing Paper doc with the provided content.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_docs_update extends Operation {}

fact Operation_docs_update_FieldValues {
  Operation_docs_update.id = "docs/update"
  Operation_docs_update.path = "/paper/docs/update"
  Operation_docs_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_update.responses
}


// Operation: POST /team/sharing_allowlist/list
// Lists Approve List entries for given team, from newest to oldest, returning
//     up to `limit` entries at a time. If there are more than `limit` entries
//     associated with the current team, more can be fetched by passing the
//     returned `cursor` to :route:`sharing_allowlist/list/continue`.
one sig Operation_sharing_allowlist_list extends Operation {}

fact Operation_sharing_allowlist_list_FieldValues {
  Operation_sharing_allowlist_list.id = "sharing_allowlist/list"
  Operation_sharing_allowlist_list.path = "/team/sharing_allowlist/list"
  Operation_sharing_allowlist_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_sharing_allowlist_list.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist_list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist_list.responses
}


// Operation: POST /file_properties/templates/get_for_team
// Get the schema for a specified template.
one sig Operation_templates_get_for_team extends Operation {}

fact Operation_templates_get_for_team_FieldValues {
  Operation_templates_get_for_team.id = "templates/get_for_team"
  Operation_templates_get_for_team.path = "/file_properties/templates/get_for_team"
  Operation_templates_get_for_team.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_get_for_team.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_get_for_team.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_get_for_team.responses
}


// Operation: POST /team/devices/revoke_device_session
// Revoke a device session of a team's member.
one sig Operation_devices_revoke_device_session extends Operation {}

fact Operation_devices_revoke_device_session_FieldValues {
  Operation_devices_revoke_device_session.id = "devices/revoke_device_session"
  Operation_devices_revoke_device_session.path = "/team/devices/revoke_device_session"
  Operation_devices_revoke_device_session.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_devices_revoke_device_session.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices_revoke_device_session.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices_revoke_device_session.responses
}


// Operation: POST /auth/token/from_oauth1
// Creates an OAuth 2.0 access token from the supplied OAuth 1.0 access token.
one sig Operation_token_from_oauth1 extends Operation {}

fact Operation_token_from_oauth1_FieldValues {
  Operation_token_from_oauth1.id = "token/from_oauth1"
  Operation_token_from_oauth1.path = "/auth/token/from_oauth1"
  Operation_token_from_oauth1.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_token_from_oauth1.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token_from_oauth1.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_token_from_oauth1.responses
}


// Operation: POST /file_properties/properties/search
// Search across property templates for particular property field values.
one sig Operation_properties_search extends Operation {}

fact Operation_properties_search_FieldValues {
  Operation_properties_search.id = "properties/search"
  Operation_properties_search.path = "/file_properties/properties/search"
  Operation_properties_search.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_search.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_search.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_search.responses
}


// Operation: POST /sharing/transfer_folder
// Transfer ownership of a shared folder to a member of the shared folder.
// 
//     User must have :field:`AccessLevel.owner` access to the shared folder to perform a transfer.
one sig Operation_transfer_folder extends Operation {}

fact Operation_transfer_folder_FieldValues {
  Operation_transfer_folder.id = "transfer_folder"
  Operation_transfer_folder.path = "/sharing/transfer_folder"
  Operation_transfer_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_transfer_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_transfer_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_transfer_folder.responses
}


// Operation: POST /files/get_thumbnail_batch
// Get thumbnails for a list of images. We allow up to 25 thumbnails in a single batch.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail.
one sig Operation_get_thumbnail_batch extends Operation {}

fact Operation_get_thumbnail_batch_FieldValues {
  Operation_get_thumbnail_batch.id = "get_thumbnail_batch"
  Operation_get_thumbnail_batch.path = "/files/get_thumbnail_batch"
  Operation_get_thumbnail_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_thumbnail_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail_batch.responses
}


// Operation: POST /team/team_folder/update_sync_settings
// Updates the sync settings on a team folder or its contents.  Use of this endpoint requires that the team has team selective sync enabled.
one sig Operation_team_folder_update_sync_settings extends Operation {}

fact Operation_team_folder_update_sync_settings_FieldValues {
  Operation_team_folder_update_sync_settings.id = "team_folder/update_sync_settings"
  Operation_team_folder_update_sync_settings.path = "/team/team_folder/update_sync_settings"
  Operation_team_folder_update_sync_settings.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_update_sync_settings.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_update_sync_settings.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_update_sync_settings.responses
}


// Operation: POST /users/get_account_batch
// Get information about multiple user accounts.  At most 300 accounts may be queried
//     per request.
one sig Operation_get_account_batch extends Operation {}

fact Operation_get_account_batch_FieldValues {
  Operation_get_account_batch.id = "get_account_batch"
  Operation_get_account_batch.path = "/users/get_account_batch"
  Operation_get_account_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_account_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_account_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_account_batch.responses
}


// Operation: POST /team/properties/template/add
// Permission : Team member file access.
one sig Operation_properties_template_add extends Operation {}

fact Operation_properties_template_add_FieldValues {
  Operation_properties_template_add.id = "properties/template/add"
  Operation_properties_template_add.path = "/team/properties/template/add"
  Operation_properties_template_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_template_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_add.responses
}


// Operation: POST /sharing/remove_file_member_2
// Removes a specified member from the file.
one sig Operation_remove_file_member_2 extends Operation {}

fact Operation_remove_file_member_2_FieldValues {
  Operation_remove_file_member_2.id = "remove_file_member_2"
  Operation_remove_file_member_2.path = "/sharing/remove_file_member_2"
  Operation_remove_file_member_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_remove_file_member_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_remove_file_member_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_remove_file_member_2.responses
}


// Operation: POST /sharing/list_folder_members/continue
// Once a cursor has been retrieved from :route:`list_folder_members`, use this to paginate
//     through all shared folder members.
one sig Operation_list_folder_members_continue extends Operation {}

fact Operation_list_folder_members_continue_FieldValues {
  Operation_list_folder_members_continue.id = "list_folder_members/continue"
  Operation_list_folder_members_continue.path = "/sharing/list_folder_members/continue"
  Operation_list_folder_members_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder_members_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_members_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_members_continue.responses
}


// Operation: POST /team/token/get_authenticated_admin
// Returns the member profile of the admin who generated the team access token used to make the call.
one sig Operation_token_get_authenticated_admin extends Operation {}

fact Operation_token_get_authenticated_admin_FieldValues {
  Operation_token_get_authenticated_admin.id = "token/get_authenticated_admin"
  Operation_token_get_authenticated_admin.path = "/team/token/get_authenticated_admin"
  Operation_token_get_authenticated_admin.method = "POST"
  // This operation has no request body
  no Operation_token_get_authenticated_admin.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_token_get_authenticated_admin.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token_get_authenticated_admin.responses
}


// Operation: POST /file_requests/list/continue
// Once a cursor has been retrieved from :route:`list:2`, use this to paginate through all
//     file requests. The cursor must come from a previous call to :route:`list:2` or
//     :route:`list/continue`.
one sig Operation_list_continue extends Operation {}

fact Operation_list_continue_FieldValues {
  Operation_list_continue.id = "list/continue"
  Operation_list_continue.path = "/file_requests/list/continue"
  Operation_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_continue.responses
}


// Operation: POST /sharing/unshare_file
// Remove all members from this file. Does not remove inherited members.
one sig Operation_unshare_file extends Operation {}

fact Operation_unshare_file_FieldValues {
  Operation_unshare_file.id = "unshare_file"
  Operation_unshare_file.path = "/sharing/unshare_file"
  Operation_unshare_file.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_unshare_file.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unshare_file.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unshare_file.responses
}


// Operation: POST /files/properties/template/get
// Execute properties/template/get
one sig Operation_properties_template_get extends Operation {}

fact Operation_properties_template_get_FieldValues {
  Operation_properties_template_get.id = "properties/template/get"
  Operation_properties_template_get.path = "/files/properties/template/get"
  Operation_properties_template_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_template_get.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_get.responses
}


// Operation: POST /paper/folders/create
// Create a new Paper folder with the provided info.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_folders_create extends Operation {}

fact Operation_folders_create_FieldValues {
  Operation_folders_create.id = "folders/create"
  Operation_folders_create.path = "/paper/folders/create"
  Operation_folders_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_folders_create.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_folders_create.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_folders_create.responses
}


// Operation: POST /team/members/list/continue:2
// Once a cursor has been retrieved from :route:`members/list:2`, use this to paginate
//     through all team members.
// 
//     Permission : Team information.
one sig Operation_members_list_continue_2 extends Operation {}

fact Operation_members_list_continue_2_FieldValues {
  Operation_members_list_continue_2.id = "members/list/continue:2"
  Operation_members_list_continue_2.path = "/team/members/list/continue:2"
  Operation_members_list_continue_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_list_continue_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_list_continue_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_list_continue_2.responses
}


// Operation: POST /team/members/suspend
// Suspend a member from a team.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members_suspend extends Operation {}

fact Operation_members_suspend_FieldValues {
  Operation_members_suspend.id = "members/suspend"
  Operation_members_suspend.path = "/team/members/suspend"
  Operation_members_suspend.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_suspend.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_suspend.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_suspend.responses
}


// Operation: POST /files/upload_session/start_batch
// This route starts batch of upload_sessions. Please refer to `upload_session/start` usage.
// 
//     Calls to this endpoint will count as data transport calls for any Dropbox
//     Business teams with a limit on the number of data transport calls allowed
//     per month. For more information, see the :link:`Data transport limit page
//     https://www.dropbox.com/developers/reference/data-transport-limit`. RPC-style endpoint: Both request and response bodies are JSON.
one sig Operation_upload_session_start_batch extends Operation {}

fact Operation_upload_session_start_batch_FieldValues {
  Operation_upload_session_start_batch.id = "upload_session/start_batch"
  Operation_upload_session_start_batch.path = "/files/upload_session/start_batch"
  Operation_upload_session_start_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_start_batch.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_start_batch.responses
}


// Operation: POST /sharing/list_mountable_folders/continue
// Once a cursor has been retrieved from :route:`list_mountable_folders`, use this to paginate through all
//     mountable shared folders. The cursor must come from a previous call to :route:`list_mountable_folders` or
//     :route:`list_mountable_folders/continue`.
one sig Operation_list_mountable_folders_continue extends Operation {}

fact Operation_list_mountable_folders_continue_FieldValues {
  Operation_list_mountable_folders_continue.id = "list_mountable_folders/continue"
  Operation_list_mountable_folders_continue.path = "/sharing/list_mountable_folders/continue"
  Operation_list_mountable_folders_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_mountable_folders_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_mountable_folders_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_mountable_folders_continue.responses
}


// Operation: POST /team/namespaces/list
// Returns a list of all team-accessible namespaces. This list includes team folders,
//     shared folders containing team members, team members' home namespaces, and team members'
//     app folders. Home namespaces and app folders are always owned by this team or members of the
//     team, but shared folders may be owned by other users or other teams. Duplicates may occur in the
//     list.
one sig Operation_namespaces_list extends Operation {}

fact Operation_namespaces_list_FieldValues {
  Operation_namespaces_list.id = "namespaces/list"
  Operation_namespaces_list.path = "/team/namespaces/list"
  Operation_namespaces_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_namespaces_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_namespaces_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_namespaces_list.responses
}


// Operation: POST /team/members/delete_profile_photo
// Deletes a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members_delete_profile_photo extends Operation {}

fact Operation_members_delete_profile_photo_FieldValues {
  Operation_members_delete_profile_photo.id = "members/delete_profile_photo"
  Operation_members_delete_profile_photo.path = "/team/members/delete_profile_photo"
  Operation_members_delete_profile_photo.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_delete_profile_photo.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_delete_profile_photo.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_delete_profile_photo.responses
}


// Operation: POST /team/features/get_values
// Get the values for one or more featues. This route allows you to check your account's
//     capability for what feature you can access or what value you have for certain features.
// 
//     Permission : Team information.
one sig Operation_features_get_values extends Operation {}

fact Operation_features_get_values_FieldValues {
  Operation_features_get_values.id = "features/get_values"
  Operation_features_get_values.path = "/team/features/get_values"
  Operation_features_get_values.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_features_get_values.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_features_get_values.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_features_get_values.responses
}


// Operation: POST /files/create_folder_batch/check
// Returns the status of an asynchronous job for :route:`create_folder_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_create_folder_batch_check extends Operation {}

fact Operation_create_folder_batch_check_FieldValues {
  Operation_create_folder_batch_check.id = "create_folder_batch/check"
  Operation_create_folder_batch_check.path = "/files/create_folder_batch/check"
  Operation_create_folder_batch_check.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_create_folder_batch_check.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder_batch_check.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_folder_batch_check.responses
}


// Operation: POST /files/get_thumbnail
// Get a thumbnail for an image.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_thumbnail extends Operation {}

fact Operation_get_thumbnail_FieldValues {
  Operation_get_thumbnail.id = "get_thumbnail"
  Operation_get_thumbnail.path = "/files/get_thumbnail"
  Operation_get_thumbnail.method = "POST"
  // This operation has no request body
  no Operation_get_thumbnail.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail.responses
}


// Operation: POST /team/groups/job_status/get
// Once an async_job_id is returned from :route:`groups/delete`,
//     :route:`groups/members/add` , or :route:`groups/members/remove`
//     use this method to poll the status of granting/revoking
//     group members' access to group-owned resources.
// 
//     Permission : Team member management.
one sig Operation_groups_job_status_get extends Operation {}

fact Operation_groups_job_status_get_FieldValues {
  Operation_groups_job_status_get.id = "groups/job_status/get"
  Operation_groups_job_status_get.path = "/team/groups/job_status/get"
  Operation_groups_job_status_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_job_status_get.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_job_status_get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_job_status_get.responses
}


// Operation: POST /team/devices/revoke_device_session_batch
// Revoke a list of device sessions of team members.
one sig Operation_devices_revoke_device_session_batch extends Operation {}

fact Operation_devices_revoke_device_session_batch_FieldValues {
  Operation_devices_revoke_device_session_batch.id = "devices/revoke_device_session_batch"
  Operation_devices_revoke_device_session_batch.path = "/team/devices/revoke_device_session_batch"
  Operation_devices_revoke_device_session_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_devices_revoke_device_session_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices_revoke_device_session_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices_revoke_device_session_batch.responses
}


// Operation: POST /files/save_url
// Save the data from a specified URL into a file in user's Dropbox.
// 
//     Note that the transfer from the URL must complete within 15 minutes, or the
//     operation will time out and the job will fail.
// 
//     If the given path already exists, the file will be renamed to avoid the
//     conflict (e.g. myfile (1).txt).
one sig Operation_save_url extends Operation {}

fact Operation_save_url_FieldValues {
  Operation_save_url.id = "save_url"
  Operation_save_url.path = "/files/save_url"
  Operation_save_url.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_save_url.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_save_url.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_save_url.responses
}


// Operation: POST /file_requests/count
// Returns the total number of file requests owned by this user. Includes both open and
//     closed file requests.
one sig Operation_count extends Operation {}

fact Operation_count_FieldValues {
  Operation_count.id = "count"
  Operation_count.path = "/file_requests/count"
  Operation_count.method = "POST"
  // This operation has no request body
  no Operation_count.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_count.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_count.responses
}


// Operation: POST /team/team_folder/get_info
// Retrieves metadata for team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_get_info extends Operation {}

fact Operation_team_folder_get_info_FieldValues {
  Operation_team_folder_get_info.id = "team_folder/get_info"
  Operation_team_folder_get_info.path = "/team/team_folder/get_info"
  Operation_team_folder_get_info.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_get_info.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_get_info.responses
}


// Operation: POST /files/properties/update
// Execute properties/update
one sig Operation_properties_update extends Operation {}

fact Operation_properties_update_FieldValues {
  Operation_properties_update.id = "properties/update"
  Operation_properties_update.path = "/files/properties/update"
  Operation_properties_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_update.responses
}


// Operation: POST /account/set_profile_photo
// Sets a user's profile photo.
one sig Operation_set_profile_photo extends Operation {}

fact Operation_set_profile_photo_FieldValues {
  Operation_set_profile_photo.id = "set_profile_photo"
  Operation_set_profile_photo.path = "/account/set_profile_photo"
  Operation_set_profile_photo.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_set_profile_photo.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_set_profile_photo.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_set_profile_photo.responses
}


// Operation: POST /contacts/delete_manual_contacts_batch
// Removes manually added contacts from the given list.
one sig Operation_delete_manual_contacts_batch extends Operation {}

fact Operation_delete_manual_contacts_batch_FieldValues {
  Operation_delete_manual_contacts_batch.id = "delete_manual_contacts_batch"
  Operation_delete_manual_contacts_batch.path = "/contacts/delete_manual_contacts_batch"
  Operation_delete_manual_contacts_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_delete_manual_contacts_batch.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_manual_contacts_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_manual_contacts_batch.responses
}


// Operation: POST /team/legal_holds/release_policy
// Releases a legal hold by Id.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_release_policy extends Operation {}

fact Operation_legal_holds_release_policy_FieldValues {
  Operation_legal_holds_release_policy.id = "legal_holds/release_policy"
  Operation_legal_holds_release_policy.path = "/team/legal_holds/release_policy"
  Operation_legal_holds_release_policy.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_release_policy.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_release_policy.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_release_policy.responses
}


// Operation: POST /files/create_folder:2
// Create a folder at a given path.
one sig Operation_create_folder_2 extends Operation {}

fact Operation_create_folder_2_FieldValues {
  Operation_create_folder_2.id = "create_folder:2"
  Operation_create_folder_2.path = "/files/create_folder:2"
  Operation_create_folder_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_create_folder_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_folder_2.responses
}


// Operation: POST /team/members/move_former_member_files
// Moves removed member's files to a different member. This endpoint initiates an asynchronous job. To obtain the final result
//     of the job, the client should periodically poll :route:`members/move_former_member_files/job_status/check`.
// 
//     Permission : Team member management.
one sig Operation_members_move_former_member_files extends Operation {}

fact Operation_members_move_former_member_files_FieldValues {
  Operation_members_move_former_member_files.id = "members/move_former_member_files"
  Operation_members_move_former_member_files.path = "/team/members/move_former_member_files"
  Operation_members_move_former_member_files.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_move_former_member_files.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_move_former_member_files.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_move_former_member_files.responses
}


// Operation: POST /files/get_metadata
// Returns the metadata for a file or folder. This is an alpha endpoint
//     compatible with the properties API.
// 
//     Note: Metadata for the root folder is unsupported.
one sig Operation_get_metadata extends Operation {}

fact Operation_get_metadata_FieldValues {
  Operation_get_metadata.id = "get_metadata"
  Operation_get_metadata.path = "/files/get_metadata"
  Operation_get_metadata.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_metadata.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_metadata.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_metadata.responses
}


// Operation: POST /file_properties/templates/get_for_user
// Get the schema for a specified template. This endpoint can't be called on a team member or admin's behalf.
one sig Operation_templates_get_for_user extends Operation {}

fact Operation_templates_get_for_user_FieldValues {
  Operation_templates_get_for_user.id = "templates/get_for_user"
  Operation_templates_get_for_user.path = "/file_properties/templates/get_for_user"
  Operation_templates_get_for_user.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_get_for_user.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_get_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_get_for_user.responses
}


// Operation: POST /sharing/mount_folder
// The current user mounts the designated folder.
// 
//     Mount a shared folder for a user after they have been added as a member.
//     Once mounted, the shared folder will appear in their Dropbox.
one sig Operation_mount_folder extends Operation {}

fact Operation_mount_folder_FieldValues {
  Operation_mount_folder.id = "mount_folder"
  Operation_mount_folder.path = "/sharing/mount_folder"
  Operation_mount_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_mount_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_mount_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_mount_folder.responses
}


// Operation: POST /sharing/list_received_files/continue
// Get more results with a cursor from :route:`list_received_files`.
one sig Operation_list_received_files_continue extends Operation {}

fact Operation_list_received_files_continue_FieldValues {
  Operation_list_received_files_continue.id = "list_received_files/continue"
  Operation_list_received_files_continue.path = "/sharing/list_received_files/continue"
  Operation_list_received_files_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_received_files_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_received_files_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_received_files_continue.responses
}


// Operation: POST /file_properties/properties/search/continue
// Once a cursor has been retrieved from :route:`properties/search`, use this to paginate through all
//     search results.
one sig Operation_properties_search_continue extends Operation {}

fact Operation_properties_search_continue_FieldValues {
  Operation_properties_search_continue.id = "properties/search/continue"
  Operation_properties_search_continue.path = "/file_properties/properties/search/continue"
  Operation_properties_search_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_search_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_search_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_search_continue.responses
}


// Operation: POST /paper/docs/folder_users/list
// Lists the users who are explicitly invited to the Paper folder in which the Paper doc
//     is contained. For private folders all users (including owner) shared on the folder
//     are listed and for team folders all non-team users shared on the folder are returned.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_folder_users_list extends Operation {}

fact Operation_docs_folder_users_list_FieldValues {
  Operation_docs_folder_users_list.id = "docs/folder_users/list"
  Operation_docs_folder_users_list.path = "/paper/docs/folder_users/list"
  Operation_docs_folder_users_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_folder_users_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_folder_users_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_folder_users_list.responses
}


// Operation: POST /team/team_folder/list
// Lists all team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_list extends Operation {}

fact Operation_team_folder_list_FieldValues {
  Operation_team_folder_list.id = "team_folder/list"
  Operation_team_folder_list.path = "/team/team_folder/list"
  Operation_team_folder_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_list.responses
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
one sig Operation_members_add_2 extends Operation {}

fact Operation_members_add_2_FieldValues {
  Operation_members_add_2.id = "members/add:2"
  Operation_members_add_2.path = "/team/members/add:2"
  Operation_members_add_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_add_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_add_2.responses
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
one sig Operation_share_folder extends Operation {}

fact Operation_share_folder_FieldValues {
  Operation_share_folder.id = "share_folder"
  Operation_share_folder.path = "/sharing/share_folder"
  Operation_share_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_share_folder.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_share_folder.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_share_folder.responses
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
one sig Operation_permanently_delete extends Operation {}

fact Operation_permanently_delete_FieldValues {
  Operation_permanently_delete.id = "permanently_delete"
  Operation_permanently_delete.path = "/files/permanently_delete"
  Operation_permanently_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_permanently_delete.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_permanently_delete.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_permanently_delete.responses
}


// Operation: POST /sharing/get_file_metadata
// Returns shared file metadata.
one sig Operation_get_file_metadata extends Operation {}

fact Operation_get_file_metadata_FieldValues {
  Operation_get_file_metadata.id = "get_file_metadata"
  Operation_get_file_metadata.path = "/sharing/get_file_metadata"
  Operation_get_file_metadata.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_file_metadata.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_metadata.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_metadata.responses
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
one sig Operation_list_revisions extends Operation {}

fact Operation_list_revisions_FieldValues {
  Operation_list_revisions.id = "list_revisions"
  Operation_list_revisions.path = "/files/list_revisions"
  Operation_list_revisions.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_revisions.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_revisions.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_revisions.responses
}


// Operation: POST /team/reports/get_activity
// Retrieves reporting data about a team's user activity.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports_get_activity extends Operation {}

fact Operation_reports_get_activity_FieldValues {
  Operation_reports_get_activity.id = "reports/get_activity"
  Operation_reports_get_activity.path = "/team/reports/get_activity"
  Operation_reports_get_activity.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_reports_get_activity.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports_get_activity.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports_get_activity.responses
}


// Operation: POST /users/get_space_usage
// Get the space usage information for the current user's account.
one sig Operation_get_space_usage extends Operation {}

fact Operation_get_space_usage_FieldValues {
  Operation_get_space_usage.id = "get_space_usage"
  Operation_get_space_usage.path = "/users/get_space_usage"
  Operation_get_space_usage.method = "POST"
  // This operation has no request body
  no Operation_get_space_usage.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_space_usage.responses
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
one sig Operation_get_events extends Operation {}

fact Operation_get_events_FieldValues {
  Operation_get_events.id = "get_events"
  Operation_get_events.path = "/team_log/get_events"
  Operation_get_events.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_events.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_events.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_events.responses
}


// Operation: POST /team/member_space_limits/excluded_users/list
// List member space limits excluded users.
one sig Operation_member_space_limits_excluded_users_list extends Operation {}

fact Operation_member_space_limits_excluded_users_list_FieldValues {
  Operation_member_space_limits_excluded_users_list.id = "member_space_limits/excluded_users/list"
  Operation_member_space_limits_excluded_users_list.path = "/team/member_space_limits/excluded_users/list"
  Operation_member_space_limits_excluded_users_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_excluded_users_list.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_excluded_users_list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_excluded_users_list.responses
}


// Operation: POST /files/copy:2
// Copy a file or folder to a different location in the user's Dropbox.
// 
//     If the source path is a folder all its contents will be copied.
one sig Operation_copy_2 extends Operation {}

fact Operation_copy_2_FieldValues {
  Operation_copy_2.id = "copy:2"
  Operation_copy_2.path = "/files/copy:2"
  Operation_copy_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_copy_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_2.responses
}


// Operation: POST /team_log/get_events/continue
// Once a cursor has been retrieved from :route:`get_events`, use this to paginate through all events.
// 
//     Permission : Team Auditing.
one sig Operation_get_events_continue extends Operation {}

fact Operation_get_events_continue_FieldValues {
  Operation_get_events_continue.id = "get_events/continue"
  Operation_get_events_continue.path = "/team_log/get_events/continue"
  Operation_get_events_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_events_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_events_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_events_continue.responses
}


// Operation: POST /files/list_folder/longpoll
// A longpoll endpoint to wait for changes on an account. In conjunction with
//     :route:`list_folder/continue`, this call gives you a low-latency way to
//     monitor an account for file changes. The connection will block until there
//     are changes available or a timeout occurs. This endpoint is useful mostly
//     for client-side apps. If you're looking for server-side notifications,
//     check out our
//     :link:`webhooks documentation https://www.dropbox.com/developers/reference/webhooks`.
one sig Operation_list_folder_longpoll extends Operation {}

fact Operation_list_folder_longpoll_FieldValues {
  Operation_list_folder_longpoll.id = "list_folder/longpoll"
  Operation_list_folder_longpoll.path = "/files/list_folder/longpoll"
  Operation_list_folder_longpoll.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder_longpoll.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_longpoll.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_longpoll.responses
}


// Operation: POST /files/list_folder/get_latest_cursor
// A way to quickly get a cursor for the folder's state. Unlike :route:`list_folder`,
//     :route:`list_folder/get_latest_cursor` doesn't return any entries. This endpoint is for app
//     which only needs to know about new files and modifications and doesn't need to know about
//     files that already exist in Dropbox.
one sig Operation_list_folder_get_latest_cursor extends Operation {}

fact Operation_list_folder_get_latest_cursor_FieldValues {
  Operation_list_folder_get_latest_cursor.id = "list_folder/get_latest_cursor"
  Operation_list_folder_get_latest_cursor.path = "/files/list_folder/get_latest_cursor"
  Operation_list_folder_get_latest_cursor.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder_get_latest_cursor.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_get_latest_cursor.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_get_latest_cursor.responses
}


// Operation: POST /team/members/unsuspend
// Unsuspend a member from a team.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members_unsuspend extends Operation {}

fact Operation_members_unsuspend_FieldValues {
  Operation_members_unsuspend.id = "members/unsuspend"
  Operation_members_unsuspend.path = "/team/members/unsuspend"
  Operation_members_unsuspend.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_unsuspend.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_unsuspend.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_unsuspend.responses
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
one sig Operation_docs_get_folder_info extends Operation {}

fact Operation_docs_get_folder_info_FieldValues {
  Operation_docs_get_folder_info.id = "docs/get_folder_info"
  Operation_docs_get_folder_info.path = "/paper/docs/get_folder_info"
  Operation_docs_get_folder_info.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_get_folder_info.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_get_folder_info.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_get_folder_info.responses
}


// Operation: POST /team/properties/template/get
// Permission : Team member file access. The scope for the route is files.team_metadata.write.
one sig Operation_properties_template_get extends Operation {}

fact Operation_properties_template_get_FieldValues {
  Operation_properties_template_get.id = "properties/template/get"
  Operation_properties_template_get.path = "/team/properties/template/get"
  Operation_properties_template_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_template_get.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_get.responses
}


// Operation: POST /sharing/update_file_member
// Changes a member's access on a shared file.
one sig Operation_update_file_member extends Operation {}

fact Operation_update_file_member_FieldValues {
  Operation_update_file_member.id = "update_file_member"
  Operation_update_file_member.path = "/sharing/update_file_member"
  Operation_update_file_member.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_update_file_member.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_file_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_file_member.responses
}


// Operation: POST /sharing/list_folders/continue
// Once a cursor has been retrieved from :route:`list_folders`, use this to paginate through all
//     shared folders. The cursor must come from a previous call to :route:`list_folders` or
//     :route:`list_folders/continue`.
one sig Operation_list_folders_continue extends Operation {}

fact Operation_list_folders_continue_FieldValues {
  Operation_list_folders_continue.id = "list_folders/continue"
  Operation_list_folders_continue.path = "/sharing/list_folders/continue"
  Operation_list_folders_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folders_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folders_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folders_continue.responses
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
one sig Operation_create_shared_link_with_settings extends Operation {}

fact Operation_create_shared_link_with_settings_FieldValues {
  Operation_create_shared_link_with_settings.id = "create_shared_link_with_settings"
  Operation_create_shared_link_with_settings.path = "/sharing/create_shared_link_with_settings"
  Operation_create_shared_link_with_settings.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_create_shared_link_with_settings.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_shared_link_with_settings.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create_shared_link_with_settings.responses
}


// Operation: POST /team/legal_holds/create_policy
// Creates new legal hold policy.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_create_policy extends Operation {}

fact Operation_legal_holds_create_policy_FieldValues {
  Operation_legal_holds_create_policy.id = "legal_holds/create_policy"
  Operation_legal_holds_create_policy.path = "/team/legal_holds/create_policy"
  Operation_legal_holds_create_policy.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_create_policy.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_create_policy.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_create_policy.responses
}


// Operation: POST /paper/docs/folder_users/list/continue
// Once a cursor has been retrieved from :route:`docs/folder_users/list`, use this to
//     paginate through all users on the Paper folder.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_folder_users_list_continue extends Operation {}

fact Operation_docs_folder_users_list_continue_FieldValues {
  Operation_docs_folder_users_list_continue.id = "docs/folder_users/list/continue"
  Operation_docs_folder_users_list_continue.path = "/paper/docs/folder_users/list/continue"
  Operation_docs_folder_users_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_folder_users_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_folder_users_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_folder_users_list_continue.responses
}


// Operation: POST /file_requests/create
// Creates a file request for this user.
one sig Operation_create extends Operation {}

fact Operation_create_FieldValues {
  Operation_create.id = "create"
  Operation_create.path = "/file_requests/create"
  Operation_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_create.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_create.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create.responses
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
one sig Operation_groups_members_remove extends Operation {}

fact Operation_groups_members_remove_FieldValues {
  Operation_groups_members_remove.id = "groups/members/remove"
  Operation_groups_members_remove.path = "/team/groups/members/remove"
  Operation_groups_members_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_members_remove.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_members_remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_members_remove.responses
}


// Operation: POST /sharing/add_folder_member
// Allows an owner or editor (if the ACL update policy allows) of a shared
//     folder to add another member.
// 
//     For the new member to get access to all the functionality for this folder,
//     you will need to call :route:`mount_folder` on their behalf.
one sig Operation_add_folder_member extends Operation {}

fact Operation_add_folder_member_FieldValues {
  Operation_add_folder_member.id = "add_folder_member"
  Operation_add_folder_member.path = "/sharing/add_folder_member"
  Operation_add_folder_member.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_add_folder_member.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_add_folder_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_add_folder_member.responses
}


// Operation: POST /files/move:2
// Move a file or folder to a different location in the user's Dropbox.
// 
//     If the source path is a folder all its contents will be moved.
one sig Operation_move_2 extends Operation {}

fact Operation_move_2_FieldValues {
  Operation_move_2.id = "move:2"
  Operation_move_2.path = "/files/move:2"
  Operation_move_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_move_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_move_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move_2.responses
}


// Operation: POST /sharing/check_remove_member_job_status
// Returns the status of an asynchronous job for sharing a folder.
one sig Operation_check_remove_member_job_status extends Operation {}

fact Operation_check_remove_member_job_status_FieldValues {
  Operation_check_remove_member_job_status.id = "check_remove_member_job_status"
  Operation_check_remove_member_job_status.path = "/sharing/check_remove_member_job_status"
  Operation_check_remove_member_job_status.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_check_remove_member_job_status.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_remove_member_job_status.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_remove_member_job_status.responses
}


// Operation: POST /check/app
// This endpoint performs App Authentication, validating the supplied app key and secret,
//     and returns the supplied string, to allow you to test your code and connection to the
//     Dropbox API. It has no other effect. If you receive an HTTP 200 response with the supplied
//     query, it indicates at least part of the Dropbox API infrastructure is working and that the
//     app key and secret valid.
one sig Operation_app extends Operation {}

fact Operation_app_FieldValues {
  Operation_app.id = "app"
  Operation_app.path = "/check/app"
  Operation_app.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_app.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_app.responses
}


// Operation: POST /files/tags/add
// Add a tag to an item. A tag is a string. The strings are automatically converted to lowercase letters. No more than 20 tags can be added to a given item.
one sig Operation_tags_add extends Operation {}

fact Operation_tags_add_FieldValues {
  Operation_tags_add.id = "tags/add"
  Operation_tags_add.path = "/files/tags/add"
  Operation_tags_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_tags_add.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags_add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags_add.responses
}


// Operation: POST /team/namespaces/list/continue
// Once a cursor has been retrieved from :route:`namespaces/list`, use this to paginate
//     through all team-accessible namespaces. Duplicates may occur in the list.
one sig Operation_namespaces_list_continue extends Operation {}

fact Operation_namespaces_list_continue_FieldValues {
  Operation_namespaces_list_continue.id = "namespaces/list/continue"
  Operation_namespaces_list_continue.path = "/team/namespaces/list/continue"
  Operation_namespaces_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_namespaces_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_namespaces_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_namespaces_list_continue.responses
}


// Operation: POST /team/team_folder/list/continue
// Once a cursor has been retrieved from :route:`team_folder/list`, use this to paginate
//     through all team folders.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_list_continue extends Operation {}

fact Operation_team_folder_list_continue_FieldValues {
  Operation_team_folder_list_continue.id = "team_folder/list/continue"
  Operation_team_folder_list_continue.path = "/team/team_folder/list/continue"
  Operation_team_folder_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_list_continue.responses
}


// Operation: POST /team/members/set_profile_photo
// Updates a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members_set_profile_photo extends Operation {}

fact Operation_members_set_profile_photo_FieldValues {
  Operation_members_set_profile_photo.id = "members/set_profile_photo"
  Operation_members_set_profile_photo.path = "/team/members/set_profile_photo"
  Operation_members_set_profile_photo.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_profile_photo.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_profile_photo.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_profile_photo.responses
}


// Operation: POST /files/save_url/check_job_status
// Check the status of a :route:`save_url` job.
one sig Operation_save_url_check_job_status extends Operation {}

fact Operation_save_url_check_job_status_FieldValues {
  Operation_save_url_check_job_status.id = "save_url/check_job_status"
  Operation_save_url_check_job_status.path = "/files/save_url/check_job_status"
  Operation_save_url_check_job_status.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_save_url_check_job_status.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_save_url_check_job_status.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_save_url_check_job_status.responses
}


// Operation: POST /team/members/set_profile_photo:2
// Updates a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members_set_profile_photo_2 extends Operation {}

fact Operation_members_set_profile_photo_2_FieldValues {
  Operation_members_set_profile_photo_2.id = "members/set_profile_photo:2"
  Operation_members_set_profile_photo_2.path = "/team/members/set_profile_photo:2"
  Operation_members_set_profile_photo_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_profile_photo_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_profile_photo_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_profile_photo_2.responses
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
one sig Operation_upload_session_finish_batch_2 extends Operation {}

fact Operation_upload_session_finish_batch_2_FieldValues {
  Operation_upload_session_finish_batch_2.id = "upload_session/finish_batch:2"
  Operation_upload_session_finish_batch_2.path = "/files/upload_session/finish_batch:2"
  Operation_upload_session_finish_batch_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_finish_batch_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_finish_batch_2.responses
}


// Operation: POST /files/restore
// Restore a specific revision of a file to the given path.
one sig Operation_restore extends Operation {}

fact Operation_restore_FieldValues {
  Operation_restore.id = "restore"
  Operation_restore.path = "/files/restore"
  Operation_restore.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_restore.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_restore.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_restore.responses
}


// Operation: POST /files/properties/add
// Execute properties/add
one sig Operation_properties_add extends Operation {}

fact Operation_properties_add_FieldValues {
  Operation_properties_add.id = "properties/add"
  Operation_properties_add.path = "/files/properties/add"
  Operation_properties_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_add.responses
}


// Operation: POST /team/member_space_limits/excluded_users/list/continue
// Continue listing member space limits excluded users.
one sig Operation_member_space_limits_excluded_users_list_continue extends Operation {}

fact Operation_member_space_limits_excluded_users_list_continue_FieldValues {
  Operation_member_space_limits_excluded_users_list_continue.id = "member_space_limits/excluded_users/list/continue"
  Operation_member_space_limits_excluded_users_list_continue.path = "/team/member_space_limits/excluded_users/list/continue"
  Operation_member_space_limits_excluded_users_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_excluded_users_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_excluded_users_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_excluded_users_list_continue.responses
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
one sig Operation_list_folder extends Operation {}

fact Operation_list_folder_FieldValues {
  Operation_list_folder.id = "list_folder"
  Operation_list_folder.path = "/files/list_folder"
  Operation_list_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder.responses
}


// Operation: POST /team/reports/get_devices
// Retrieves reporting data about a team's linked devices.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports_get_devices extends Operation {}

fact Operation_reports_get_devices_FieldValues {
  Operation_reports_get_devices.id = "reports/get_devices"
  Operation_reports_get_devices.path = "/team/reports/get_devices"
  Operation_reports_get_devices.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_reports_get_devices.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports_get_devices.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports_get_devices.responses
}


// Operation: POST /team/groups/update
// Updates a group's name and/or external ID.
// 
//     Permission : Team member management.
one sig Operation_groups_update extends Operation {}

fact Operation_groups_update_FieldValues {
  Operation_groups_update.id = "groups/update"
  Operation_groups_update.path = "/team/groups/update"
  Operation_groups_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_update.responses
}


// Operation: POST /file_properties/templates/add_for_user
// Add a template associated with a user. See :route:`properties/add` to add properties to a file. This
//     endpoint can't be called on a team member or admin's behalf.
one sig Operation_templates_add_for_user extends Operation {}

fact Operation_templates_add_for_user_FieldValues {
  Operation_templates_add_for_user.id = "templates/add_for_user"
  Operation_templates_add_for_user.path = "/file_properties/templates/add_for_user"
  Operation_templates_add_for_user.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_add_for_user.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_add_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_add_for_user.responses
}


// Operation: POST /team/groups/members/add
// Adds members to a group.
// 
//     The members are added immediately. However the granting of group-owned resources
//     may take additional time.
//     Use the :route:`groups/job_status/get` to determine whether this process has completed.
// 
//     Permission : Team member management.
one sig Operation_groups_members_add extends Operation {}

fact Operation_groups_members_add_FieldValues {
  Operation_groups_members_add.id = "groups/members/add"
  Operation_groups_members_add.path = "/team/groups/members/add"
  Operation_groups_members_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_members_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_members_add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_members_add.responses
}


// Operation: POST /team/groups/members/list/continue
// Once a cursor has been retrieved from :route:`groups/members/list`, use this to paginate
//     through all members of the group.
// 
//     Permission : Team information.
one sig Operation_groups_members_list_continue extends Operation {}

fact Operation_groups_members_list_continue_FieldValues {
  Operation_groups_members_list_continue.id = "groups/members/list/continue"
  Operation_groups_members_list_continue.path = "/team/groups/members/list/continue"
  Operation_groups_members_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_members_list_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_members_list_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_members_list_continue.responses
}


// Operation: POST /sharing/list_folder_members
// Returns shared folder membership by its folder ID.
one sig Operation_list_folder_members extends Operation {}

fact Operation_list_folder_members_FieldValues {
  Operation_list_folder_members.id = "list_folder_members"
  Operation_list_folder_members.path = "/sharing/list_folder_members"
  Operation_list_folder_members.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder_members.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_members.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_members.responses
}


// Operation: POST /team/member_space_limits/set_custom_quota
// Set users custom quota. Custom quota has to be at least 15GB.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits_set_custom_quota extends Operation {}

fact Operation_member_space_limits_set_custom_quota_FieldValues {
  Operation_member_space_limits_set_custom_quota.id = "member_space_limits/set_custom_quota"
  Operation_member_space_limits_set_custom_quota.path = "/team/member_space_limits/set_custom_quota"
  Operation_member_space_limits_set_custom_quota.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_set_custom_quota.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_set_custom_quota.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_set_custom_quota.responses
}


// Operation: POST /sharing/list_mountable_folders
// Return the list of all shared folders the current user can mount or unmount.
one sig Operation_list_mountable_folders extends Operation {}

fact Operation_list_mountable_folders_FieldValues {
  Operation_list_mountable_folders.id = "list_mountable_folders"
  Operation_list_mountable_folders.path = "/sharing/list_mountable_folders"
  Operation_list_mountable_folders.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_mountable_folders.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_mountable_folders.responses
}


// Operation: POST /sharing/list_folders
// Return the list of all shared folders the current user has access to.
one sig Operation_list_folders extends Operation {}

fact Operation_list_folders_FieldValues {
  Operation_list_folders.id = "list_folders"
  Operation_list_folders.path = "/sharing/list_folders"
  Operation_list_folders.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folders.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folders.responses
}


// Operation: POST /team/legal_holds/list_held_revisions
// List the file metadata that's under the hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_list_held_revisions extends Operation {}

fact Operation_legal_holds_list_held_revisions_FieldValues {
  Operation_legal_holds_list_held_revisions.id = "legal_holds/list_held_revisions"
  Operation_legal_holds_list_held_revisions.path = "/team/legal_holds/list_held_revisions"
  Operation_legal_holds_list_held_revisions.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_list_held_revisions.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_list_held_revisions.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_list_held_revisions.responses
}


// Operation: POST /team/team_folder/activate
// Sets an archived team folder's status to active.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_activate extends Operation {}

fact Operation_team_folder_activate_FieldValues {
  Operation_team_folder_activate.id = "team_folder/activate"
  Operation_team_folder_activate.path = "/team/team_folder/activate"
  Operation_team_folder_activate.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_activate.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_activate.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_activate.responses
}


// Operation: POST /paper/docs/sharing_policy/get
// Gets the default sharing policy for the given Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_sharing_policy_get extends Operation {}

fact Operation_docs_sharing_policy_get_FieldValues {
  Operation_docs_sharing_policy_get.id = "docs/sharing_policy/get"
  Operation_docs_sharing_policy_get.path = "/paper/docs/sharing_policy/get"
  Operation_docs_sharing_policy_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_sharing_policy_get.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_sharing_policy_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_sharing_policy_get.responses
}


// Operation: POST /files/get_thumbnail:2
// Get a thumbnail for an image.
// 
//     This method currently supports files with the following file extensions:
//     jpg, jpeg, png, tiff, tif, gif, webp, ppm and bmp. Photos that are larger than 20MB
//     in size won't be converted to a thumbnail. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_get_thumbnail_2 extends Operation {}

fact Operation_get_thumbnail_2_FieldValues {
  Operation_get_thumbnail_2.id = "get_thumbnail:2"
  Operation_get_thumbnail_2.path = "/files/get_thumbnail:2"
  Operation_get_thumbnail_2.method = "POST"
  // This operation has no request body
  no Operation_get_thumbnail_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_thumbnail_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_thumbnail_2.responses
}


// Operation: POST /team/members/secondary_emails/delete
// Delete secondary emails from users
// 
//     Permission : Team member management.
// 
//     Users will be notified of deletions of verified secondary emails at both the secondary email and their primary email.
one sig Operation_members_secondary_emails_delete extends Operation {}

fact Operation_members_secondary_emails_delete_FieldValues {
  Operation_members_secondary_emails_delete.id = "members/secondary_emails/delete"
  Operation_members_secondary_emails_delete.path = "/team/members/secondary_emails/delete"
  Operation_members_secondary_emails_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_secondary_emails_delete.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_secondary_emails_delete.responses
}


// Operation: POST /file_properties/templates/remove_for_team
// Permanently removes the specified template created from :route:`templates/add_for_user`.
//     All properties associated with the template will also be removed. This action
//     cannot be undone.
one sig Operation_templates_remove_for_team extends Operation {}

fact Operation_templates_remove_for_team_FieldValues {
  Operation_templates_remove_for_team.id = "templates/remove_for_team"
  Operation_templates_remove_for_team.path = "/file_properties/templates/remove_for_team"
  Operation_templates_remove_for_team.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_remove_for_team.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_remove_for_team.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_remove_for_team.responses
}


// Operation: POST /team/linked_apps/list_members_linked_apps
// List all applications linked to the team members' accounts.
// 
//     Note, this endpoint doesn't list any team-linked applications.
one sig Operation_linked_apps_list_members_linked_apps extends Operation {}

fact Operation_linked_apps_list_members_linked_apps_FieldValues {
  Operation_linked_apps_list_members_linked_apps.id = "linked_apps/list_members_linked_apps"
  Operation_linked_apps_list_members_linked_apps.path = "/team/linked_apps/list_members_linked_apps"
  Operation_linked_apps_list_members_linked_apps.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_linked_apps_list_members_linked_apps.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps_list_members_linked_apps.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps_list_members_linked_apps.responses
}


// Operation: POST /team/members/remove/job_status/get
// Once an async_job_id is returned from :route:`members/remove` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members_remove_job_status_get extends Operation {}

fact Operation_members_remove_job_status_get_FieldValues {
  Operation_members_remove_job_status_get.id = "members/remove/job_status/get"
  Operation_members_remove_job_status_get.path = "/team/members/remove/job_status/get"
  Operation_members_remove_job_status_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_remove_job_status_get.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_remove_job_status_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_remove_job_status_get.responses
}


// Operation: POST /sharing/get_folder_metadata
// Returns shared folder metadata by its folder ID.
one sig Operation_get_folder_metadata extends Operation {}

fact Operation_get_folder_metadata_FieldValues {
  Operation_get_folder_metadata.id = "get_folder_metadata"
  Operation_get_folder_metadata.path = "/sharing/get_folder_metadata"
  Operation_get_folder_metadata.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_folder_metadata.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_folder_metadata.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_folder_metadata.responses
}


// Operation: POST /sharing/check_job_status
// Returns the status of an asynchronous job.
one sig Operation_check_job_status extends Operation {}

fact Operation_check_job_status_FieldValues {
  Operation_check_job_status.id = "check_job_status"
  Operation_check_job_status.path = "/sharing/check_job_status"
  Operation_check_job_status.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_check_job_status.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_check_job_status.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_check_job_status.responses
}


// Operation: POST /files/get_file_lock_batch
// 
//     Return the lock metadata for the given list of paths.
//     
one sig Operation_get_file_lock_batch extends Operation {}

fact Operation_get_file_lock_batch_FieldValues {
  Operation_get_file_lock_batch.id = "get_file_lock_batch"
  Operation_get_file_lock_batch.path = "/files/get_file_lock_batch"
  Operation_get_file_lock_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_file_lock_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_lock_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_lock_batch.responses
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
one sig Operation_get_temporary_upload_link extends Operation {}

fact Operation_get_temporary_upload_link_FieldValues {
  Operation_get_temporary_upload_link.id = "get_temporary_upload_link"
  Operation_get_temporary_upload_link.path = "/files/get_temporary_upload_link"
  Operation_get_temporary_upload_link.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_temporary_upload_link.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_temporary_upload_link.responses
}


// Operation: POST /team/reports/get_storage
// Retrieves reporting data about a team's storage usage.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports_get_storage extends Operation {}

fact Operation_reports_get_storage_FieldValues {
  Operation_reports_get_storage.id = "reports/get_storage"
  Operation_reports_get_storage.path = "/team/reports/get_storage"
  Operation_reports_get_storage.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_reports_get_storage.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports_get_storage.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports_get_storage.responses
}


// Operation: POST /files/export
// Export a file from a user's Dropbox. This route only supports exporting files that cannot be downloaded directly
//      and whose :field:`ExportResult.file_metadata` has :field:`ExportInfo.export_as` populated. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_export extends Operation {}

fact Operation_export_FieldValues {
  Operation_export.id = "export"
  Operation_export.path = "/files/export"
  Operation_export.method = "POST"
  // This operation has no request body
  no Operation_export.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_export.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_export.responses
}


// Operation: POST /team/groups/list/continue
// Once a cursor has been retrieved from :route:`groups/list`, use this to paginate
//     through all groups.
// 
//     Permission : Team Information.
one sig Operation_groups_list_continue extends Operation {}

fact Operation_groups_list_continue_FieldValues {
  Operation_groups_list_continue.id = "groups/list/continue"
  Operation_groups_list_continue.path = "/team/groups/list/continue"
  Operation_groups_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_list_continue.responses
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
one sig Operation_members_add extends Operation {}

fact Operation_members_add_FieldValues {
  Operation_members_add.id = "members/add"
  Operation_members_add.path = "/team/members/add"
  Operation_members_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_add.responses
}


// Operation: POST /team/groups/members/set_access_type
// Sets a member's access type in a group.
// 
//     Permission : Team member management.
one sig Operation_groups_members_set_access_type extends Operation {}

fact Operation_groups_members_set_access_type_FieldValues {
  Operation_groups_members_set_access_type.id = "groups/members/set_access_type"
  Operation_groups_members_set_access_type.path = "/team/groups/members/set_access_type"
  Operation_groups_members_set_access_type.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_members_set_access_type.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_members_set_access_type.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_members_set_access_type.responses
}


// Operation: POST /team/members/secondary_emails/add
// Add secondary emails to users.
// 
//     Permission : Team member management.
// 
//     Emails that are on verified domains will be verified automatically.
//     For each email address not on a verified domain a verification email will be sent.
one sig Operation_members_secondary_emails_add extends Operation {}

fact Operation_members_secondary_emails_add_FieldValues {
  Operation_members_secondary_emails_add.id = "members/secondary_emails/add"
  Operation_members_secondary_emails_add.path = "/team/members/secondary_emails/add"
  Operation_members_secondary_emails_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_secondary_emails_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_secondary_emails_add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_secondary_emails_add.responses
}


// Operation: POST /team/sharing_allowlist/list/continue
// Lists entries associated with given team, starting from a the cursor. See :route:`sharing_allowlist/list`.
one sig Operation_sharing_allowlist_list_continue extends Operation {}

fact Operation_sharing_allowlist_list_continue_FieldValues {
  Operation_sharing_allowlist_list_continue.id = "sharing_allowlist/list/continue"
  Operation_sharing_allowlist_list_continue.path = "/team/sharing_allowlist/list/continue"
  Operation_sharing_allowlist_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_sharing_allowlist_list_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist_list_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist_list_continue.responses
}


// Operation: POST /team/properties/template/update
// Permission : Team member file access.
one sig Operation_properties_template_update extends Operation {}

fact Operation_properties_template_update_FieldValues {
  Operation_properties_template_update.id = "properties/template/update"
  Operation_properties_template_update.path = "/team/properties/template/update"
  Operation_properties_template_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_template_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_update.responses
}


// Operation: POST /sharing/modify_shared_link_settings
// Modify the shared link's settings.
// 
//     If the requested visibility conflict with the shared links policy of the team or the
//     shared folder (in case the linked file is part of a shared folder) then the
//     :field:`LinkPermissions.resolved_visibility` of the returned :type:`SharedLinkMetadata` will
//     reflect the actual visibility of the shared link and the
//     :field:`LinkPermissions.requested_visibility` will reflect the requested visibility.
one sig Operation_modify_shared_link_settings extends Operation {}

fact Operation_modify_shared_link_settings_FieldValues {
  Operation_modify_shared_link_settings.id = "modify_shared_link_settings"
  Operation_modify_shared_link_settings.path = "/sharing/modify_shared_link_settings"
  Operation_modify_shared_link_settings.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_modify_shared_link_settings.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_modify_shared_link_settings.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_modify_shared_link_settings.responses
}


// Operation: POST /file_properties/templates/add_for_team
// Add a template associated with a team. See :route:`properties/add` to add properties to a file or folder.
// 
//     Note: this endpoint will create team-owned templates.
one sig Operation_templates_add_for_team extends Operation {}

fact Operation_templates_add_for_team_FieldValues {
  Operation_templates_add_for_team.id = "templates/add_for_team"
  Operation_templates_add_for_team.path = "/file_properties/templates/add_for_team"
  Operation_templates_add_for_team.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_add_for_team.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_add_for_team.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_add_for_team.responses
}


// Operation: POST /paper/docs/list
// Return the list of all Paper docs according to the argument specifications. To iterate
//     over through the full pagination, pass the cursor to :route:`docs/list/continue`.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_list extends Operation {}

fact Operation_docs_list_FieldValues {
  Operation_docs_list.id = "docs/list"
  Operation_docs_list.path = "/paper/docs/list"
  Operation_docs_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_list.responses
}


// Operation: POST /openid/userinfo
// This route is used for refreshing the info that is found in the id_token during the OIDC flow.
//     This route doesn't require any arguments and will use the scopes approved for the given access token.
one sig Operation_userinfo extends Operation {}

fact Operation_userinfo_FieldValues {
  Operation_userinfo.id = "userinfo"
  Operation_userinfo.path = "/openid/userinfo"
  Operation_userinfo.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_userinfo.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_userinfo.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_userinfo.responses
}


// Operation: POST /team/team_folder/create
// Creates a new, active, team folder with no members. This endpoint can only be used for teams
//     that do not already have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_create extends Operation {}

fact Operation_team_folder_create_FieldValues {
  Operation_team_folder_create.id = "team_folder/create"
  Operation_team_folder_create.path = "/team/team_folder/create"
  Operation_team_folder_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_create.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_create.responses
}


// Operation: POST /file_properties/properties/add
// Add property groups to a Dropbox file. See :route:`templates/add_for_user` or
//     :route:`templates/add_for_team` to create new templates.
one sig Operation_properties_add extends Operation {}

fact Operation_properties_add_FieldValues {
  Operation_properties_add.id = "properties/add"
  Operation_properties_add.path = "/file_properties/properties/add"
  Operation_properties_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_add.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_add.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_add.responses
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
one sig Operation_members_remove extends Operation {}

fact Operation_members_remove_FieldValues {
  Operation_members_remove.id = "members/remove"
  Operation_members_remove.path = "/team/members/remove"
  Operation_members_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_remove.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_remove.responses
}


// Operation: POST /files/delete:2
// Delete the file or folder at a given path.
// 
//     If the path is a folder, all its contents will be deleted too.
// 
//     A successful response indicates that the file or folder was deleted. The returned metadata will
//     be the corresponding :type:`FileMetadata` or :type:`FolderMetadata` for the item at time of
//     deletion, and not a :type:`DeletedMetadata` object.
one sig Operation_delete_2 extends Operation {}

fact Operation_delete_2_FieldValues {
  Operation_delete_2.id = "delete:2"
  Operation_delete_2.path = "/files/delete:2"
  Operation_delete_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_delete_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_2.responses
}


// Operation: POST /team/members/set_profile:2
// Updates a team member's profile.
// 
//     Permission : Team member management.
one sig Operation_members_set_profile_2 extends Operation {}

fact Operation_members_set_profile_2_FieldValues {
  Operation_members_set_profile_2.id = "members/set_profile:2"
  Operation_members_set_profile_2.path = "/team/members/set_profile:2"
  Operation_members_set_profile_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_profile_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_profile_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_profile_2.responses
}


// Operation: POST /team/members/move_former_member_files/job_status/check
// Once an async_job_id is returned from :route:`members/move_former_member_files` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members_move_former_member_files_job_status_check extends Operation {}

fact Operation_members_move_former_member_files_job_status_check_FieldValues {
  Operation_members_move_former_member_files_job_status_check.id = "members/move_former_member_files/job_status/check"
  Operation_members_move_former_member_files_job_status_check.path = "/team/members/move_former_member_files/job_status/check"
  Operation_members_move_former_member_files_job_status_check.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_move_former_member_files_job_status_check.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_move_former_member_files_job_status_check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_move_former_member_files_job_status_check.responses
}


// Operation: POST /sharing/unmount_folder
// The current user unmounts the designated folder. They can re-mount the
//     folder at a later time using :route:`mount_folder`.
one sig Operation_unmount_folder extends Operation {}

fact Operation_unmount_folder_FieldValues {
  Operation_unmount_folder.id = "unmount_folder"
  Operation_unmount_folder.path = "/sharing/unmount_folder"
  Operation_unmount_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_unmount_folder.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unmount_folder.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unmount_folder.responses
}


// Operation: POST /file_requests/delete_all_closed
// Delete all closed file requests owned by this user.
one sig Operation_delete_all_closed extends Operation {}

fact Operation_delete_all_closed_FieldValues {
  Operation_delete_all_closed.id = "delete_all_closed"
  Operation_delete_all_closed.path = "/file_requests/delete_all_closed"
  Operation_delete_all_closed.method = "POST"
  // This operation has no request body
  no Operation_delete_all_closed.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_all_closed.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_all_closed.responses
}


// Operation: POST /files/list_folder/continue
// Once a cursor has been retrieved from :route:`list_folder`, use this to paginate through all
//     files and retrieve updates to the folder, following the same rules as documented for
//     :route:`list_folder`.
one sig Operation_list_folder_continue extends Operation {}

fact Operation_list_folder_continue_FieldValues {
  Operation_list_folder_continue.id = "list_folder/continue"
  Operation_list_folder_continue.path = "/files/list_folder/continue"
  Operation_list_folder_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_folder_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_folder_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_folder_continue.responses
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
one sig Operation_upload_session_start extends Operation {}

fact Operation_upload_session_start_FieldValues {
  Operation_upload_session_start.id = "upload_session/start"
  Operation_upload_session_start.path = "/files/upload_session/start"
  Operation_upload_session_start.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_start.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session_start.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_start.responses
}


// Operation: POST /team/groups/delete
// Deletes a group.
// 
//     The group is deleted immediately. However the revoking of group-owned resources
//     may take additional time.
//     Use the :route:`groups/job_status/get` to determine whether this process has completed.
// 
//     Permission : Team member management.
one sig Operation_groups_delete extends Operation {}

fact Operation_groups_delete_FieldValues {
  Operation_groups_delete.id = "groups/delete"
  Operation_groups_delete.path = "/team/groups/delete"
  Operation_groups_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_delete.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_delete.responses
}


// Operation: POST /auth/token/revoke
// Disables the access token used to authenticate the call.
//     If there is a corresponding refresh token for the access token,
//     this disables that refresh token, as well as any other access tokens for that refresh token.
one sig Operation_token_revoke extends Operation {}

fact Operation_token_revoke_FieldValues {
  Operation_token_revoke.id = "token/revoke"
  Operation_token_revoke.path = "/auth/token/revoke"
  Operation_token_revoke.method = "POST"
  // This operation has no request body
  no Operation_token_revoke.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_token_revoke.responses
}


// Operation: POST /sharing/get_shared_link_metadata
// Get the shared link's metadata.
one sig Operation_get_shared_link_metadata extends Operation {}

fact Operation_get_shared_link_metadata_FieldValues {
  Operation_get_shared_link_metadata.id = "get_shared_link_metadata"
  Operation_get_shared_link_metadata.path = "/sharing/get_shared_link_metadata"
  Operation_get_shared_link_metadata.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_shared_link_metadata.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_shared_link_metadata.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_shared_link_metadata.responses
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
one sig Operation_docs_users_add extends Operation {}

fact Operation_docs_users_add_FieldValues {
  Operation_docs_users_add.id = "docs/users/add"
  Operation_docs_users_add.path = "/paper/docs/users/add"
  Operation_docs_users_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_users_add.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_users_add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_users_add.responses
}


// Operation: POST /team/linked_apps/revoke_linked_app
// Revoke a linked application of the team member.
one sig Operation_linked_apps_revoke_linked_app extends Operation {}

fact Operation_linked_apps_revoke_linked_app_FieldValues {
  Operation_linked_apps_revoke_linked_app.id = "linked_apps/revoke_linked_app"
  Operation_linked_apps_revoke_linked_app.path = "/team/linked_apps/revoke_linked_app"
  Operation_linked_apps_revoke_linked_app.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_linked_apps_revoke_linked_app.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps_revoke_linked_app.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps_revoke_linked_app.responses
}


// Operation: POST /file_requests/delete
// Delete a batch of closed file requests.
one sig Operation_delete extends Operation {}

fact Operation_delete_FieldValues {
  Operation_delete.id = "delete"
  Operation_delete.path = "/file_requests/delete"
  Operation_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_delete.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete.responses
}


// Operation: POST /team/linked_apps/list_member_linked_apps
// List all linked applications of the team member.
// 
//     Note, this endpoint does not list any team-linked applications.
one sig Operation_linked_apps_list_member_linked_apps extends Operation {}

fact Operation_linked_apps_list_member_linked_apps_FieldValues {
  Operation_linked_apps_list_member_linked_apps.id = "linked_apps/list_member_linked_apps"
  Operation_linked_apps_list_member_linked_apps.path = "/team/linked_apps/list_member_linked_apps"
  Operation_linked_apps_list_member_linked_apps.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_linked_apps_list_member_linked_apps.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_linked_apps_list_member_linked_apps.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_linked_apps_list_member_linked_apps.responses
}


// Operation: POST /users/get_current_account
// Get information about the current user's account.
one sig Operation_get_current_account extends Operation {}

fact Operation_get_current_account_FieldValues {
  Operation_get_current_account.id = "get_current_account"
  Operation_get_current_account.path = "/users/get_current_account"
  Operation_get_current_account.method = "POST"
  // This operation has no request body
  no Operation_get_current_account.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_current_account.responses
}


// Operation: POST /file_requests/update
// Update a file request.
one sig Operation_update extends Operation {}

fact Operation_update_FieldValues {
  Operation_update.id = "update"
  Operation_update.path = "/file_requests/update"
  Operation_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update.responses
}


// Operation: POST /sharing/list_file_members/batch
// Get members of multiple files at once. The arguments
//     to this route are more limited, and the limit on query result size per file
//     is more strict. To customize the results more, use the individual file
//     endpoint.
// 
//     Inherited users and groups are not included in the result, and permissions are not
//     returned for this endpoint.
one sig Operation_list_file_members_batch extends Operation {}

fact Operation_list_file_members_batch_FieldValues {
  Operation_list_file_members_batch.id = "list_file_members/batch"
  Operation_list_file_members_batch.path = "/sharing/list_file_members/batch"
  Operation_list_file_members_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_file_members_batch.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members_batch.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members_batch.responses
}


// Operation: POST /file_properties/properties/remove
// Permanently removes the specified property group from the file. To remove specific property field key
//     value pairs, see :route:`properties/update`.
//     To update a template, see
//     :route:`templates/update_for_user` or :route:`templates/update_for_team`.
//     To remove a template, see
//     :route:`templates/remove_for_user` or :route:`templates/remove_for_team`.
one sig Operation_properties_remove extends Operation {}

fact Operation_properties_remove_FieldValues {
  Operation_properties_remove.id = "properties/remove"
  Operation_properties_remove.path = "/file_properties/properties/remove"
  Operation_properties_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_remove.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_remove.responses
}


// Operation: POST /file_properties/templates/list_for_team
// Get the template identifiers for a team. To get the schema of
//     each template use :route:`templates/get_for_team`.
one sig Operation_templates_list_for_team extends Operation {}

fact Operation_templates_list_for_team_FieldValues {
  Operation_templates_list_for_team.id = "templates/list_for_team"
  Operation_templates_list_for_team.path = "/file_properties/templates/list_for_team"
  Operation_templates_list_for_team.method = "POST"
  // This operation has no request body
  no Operation_templates_list_for_team.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_list_for_team.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_list_for_team.responses
}


// Operation: POST /team/sharing_allowlist/add
// Endpoint adds Approve List entries. Changes are effective immediately.
//     Changes are committed in transaction. In case of single validation error - all entries are rejected.
//     Valid domains (RFC-1034/5) and emails (RFC-5322/822) are accepted.
//     Added entries cannot overflow limit of 10000 entries per team.
//     Maximum 100 entries per call is allowed.
one sig Operation_sharing_allowlist_add extends Operation {}

fact Operation_sharing_allowlist_add_FieldValues {
  Operation_sharing_allowlist_add.id = "sharing_allowlist/add"
  Operation_sharing_allowlist_add.path = "/team/sharing_allowlist/add"
  Operation_sharing_allowlist_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_sharing_allowlist_add.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist_add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist_add.responses
}


// Operation: POST /team/legal_holds/update_policy
// Updates a legal hold.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_update_policy extends Operation {}

fact Operation_legal_holds_update_policy_FieldValues {
  Operation_legal_holds_update_policy.id = "legal_holds/update_policy"
  Operation_legal_holds_update_policy.path = "/team/legal_holds/update_policy"
  Operation_legal_holds_update_policy.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_update_policy.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_update_policy.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_update_policy.responses
}


// Operation: POST /team/members/set_admin_permissions:2
// Updates a team member's permissions.
// 
//     Permission : Team member management.
one sig Operation_members_set_admin_permissions_2 extends Operation {}

fact Operation_members_set_admin_permissions_2_FieldValues {
  Operation_members_set_admin_permissions_2.id = "members/set_admin_permissions:2"
  Operation_members_set_admin_permissions_2.path = "/team/members/set_admin_permissions:2"
  Operation_members_set_admin_permissions_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_admin_permissions_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_admin_permissions_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_admin_permissions_2.responses
}


// Operation: POST /sharing/relinquish_file_membership
// The current user relinquishes their membership in the designated file.
//     Note that the current user may still have inherited access to this file
//     through the parent folder.
one sig Operation_relinquish_file_membership extends Operation {}

fact Operation_relinquish_file_membership_FieldValues {
  Operation_relinquish_file_membership.id = "relinquish_file_membership"
  Operation_relinquish_file_membership.path = "/sharing/relinquish_file_membership"
  Operation_relinquish_file_membership.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_relinquish_file_membership.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_relinquish_file_membership.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_relinquish_file_membership.responses
}


// Operation: POST /files/upload
// Create a new file with the contents provided in the request. Note that the
//     behavior of this alpha endpoint is unstable and subject to change.
// 
//     Do not use this to upload a file larger than 150 MB. Instead, create an
//     upload session with :route:`upload_session/start`. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_upload extends Operation {}

fact Operation_upload_FieldValues {
  Operation_upload.id = "upload"
  Operation_upload.path = "/files/upload"
  Operation_upload.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload.responses
}


// Operation: POST /check/user
// This endpoint performs User Authentication, validating the supplied access token,
//     and returns the supplied string, to allow you to test your code and connection to the
//     Dropbox API. It has no other effect. If you receive an HTTP 200 response with the supplied
//     query, it indicates at least part of the Dropbox API infrastructure is working and that the
//     access token is valid.
one sig Operation_user extends Operation {}

fact Operation_user_FieldValues {
  Operation_user.id = "user"
  Operation_user.path = "/check/user"
  Operation_user.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_user.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_user.responses
}


// Operation: POST /team/team_folder/rename
// Changes an active team folder's name.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_rename extends Operation {}

fact Operation_team_folder_rename_FieldValues {
  Operation_team_folder_rename.id = "team_folder/rename"
  Operation_team_folder_rename.path = "/team/team_folder/rename"
  Operation_team_folder_rename.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_rename.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_rename.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_rename.responses
}


// Operation: POST /sharing/list_file_members
// Use to obtain the members who have been invited to a file, both inherited
//     and uninherited members.
one sig Operation_list_file_members extends Operation {}

fact Operation_list_file_members_FieldValues {
  Operation_list_file_members.id = "list_file_members"
  Operation_list_file_members.path = "/sharing/list_file_members"
  Operation_list_file_members.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_file_members.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members.responses
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
one sig Operation_docs_sharing_policy_set extends Operation {}

fact Operation_docs_sharing_policy_set_FieldValues {
  Operation_docs_sharing_policy_set.id = "docs/sharing_policy/set"
  Operation_docs_sharing_policy_set.path = "/paper/docs/sharing_policy/set"
  Operation_docs_sharing_policy_set.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_sharing_policy_set.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_sharing_policy_set.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_sharing_policy_set.responses
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
one sig Operation_docs_users_list extends Operation {}

fact Operation_docs_users_list_FieldValues {
  Operation_docs_users_list.id = "docs/users/list"
  Operation_docs_users_list.path = "/paper/docs/users/list"
  Operation_docs_users_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_users_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_users_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_users_list.responses
}


// Operation: POST /paper/docs/create
// Creates a new Paper doc with the provided content.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information. Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_docs_create extends Operation {}

fact Operation_docs_create_FieldValues {
  Operation_docs_create.id = "docs/create"
  Operation_docs_create.path = "/paper/docs/create"
  Operation_docs_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_create.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_create.responses
}


// Operation: POST /paper/docs/users/list/continue
// Once a cursor has been retrieved from :route:`docs/users/list`, use this to
//     paginate through all users on the Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_users_list_continue extends Operation {}

fact Operation_docs_users_list_continue_FieldValues {
  Operation_docs_users_list_continue.id = "docs/users/list/continue"
  Operation_docs_users_list_continue.path = "/paper/docs/users/list/continue"
  Operation_docs_users_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_users_list_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_users_list_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_users_list_continue.responses
}


// Operation: POST /file_requests/get
// Returns the specified file request.
one sig Operation_get extends Operation {}

fact Operation_get_FieldValues {
  Operation_get.id = "get"
  Operation_get.path = "/file_requests/get"
  Operation_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get.responses
}


// Operation: POST /team/reports/get_membership
// Retrieves reporting data about a team's membership.
//     Deprecated: Will be removed on July 1st 2021.
one sig Operation_reports_get_membership extends Operation {}

fact Operation_reports_get_membership_FieldValues {
  Operation_reports_get_membership.id = "reports/get_membership"
  Operation_reports_get_membership.path = "/team/reports/get_membership"
  Operation_reports_get_membership.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_reports_get_membership.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_reports_get_membership.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_reports_get_membership.responses
}


// Operation: POST /files/create_folder_batch
// Create multiple folders at once.
// 
//     This route is asynchronous for large batches, which returns a job ID immediately and runs
//     the create folder batch asynchronously. Otherwise, creates the folders and returns the result
//     synchronously for smaller inputs. You can force asynchronous behaviour by using the
//     :field:`CreateFolderBatchArg.force_async` flag.  Use :route:`create_folder_batch/check` to check
//     the job status.
one sig Operation_create_folder_batch extends Operation {}

fact Operation_create_folder_batch_FieldValues {
  Operation_create_folder_batch.id = "create_folder_batch"
  Operation_create_folder_batch.path = "/files/create_folder_batch"
  Operation_create_folder_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_create_folder_batch.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_create_folder_batch.responses
}


// Operation: POST /files/unlock_file_batch
// 
//     Unlock the files at the given paths. A locked file can only be unlocked by the lock holder
//     or, if a business account, a team admin. A successful response indicates that the file has
//     been unlocked. Returns a list of the unlocked file paths and their metadata after
//     this operation.
//     
one sig Operation_unlock_file_batch extends Operation {}

fact Operation_unlock_file_batch_FieldValues {
  Operation_unlock_file_batch.id = "unlock_file_batch"
  Operation_unlock_file_batch.path = "/files/unlock_file_batch"
  Operation_unlock_file_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_unlock_file_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unlock_file_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unlock_file_batch.responses
}


// Operation: POST /file_properties/templates/update_for_user
// Update a template associated with a user. This route can update the template name,
//     the template description and add optional properties to templates. This endpoint can't
//     be called on a team member or admin's behalf.
one sig Operation_templates_update_for_user extends Operation {}

fact Operation_templates_update_for_user_FieldValues {
  Operation_templates_update_for_user.id = "templates/update_for_user"
  Operation_templates_update_for_user.path = "/file_properties/templates/update_for_user"
  Operation_templates_update_for_user.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_update_for_user.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_update_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_update_for_user.responses
}


// Operation: POST /team/members/list/continue
// Once a cursor has been retrieved from :route:`members/list`, use this to paginate
//     through all team members.
// 
//     Permission : Team information.
one sig Operation_members_list_continue extends Operation {}

fact Operation_members_list_continue_FieldValues {
  Operation_members_list_continue.id = "members/list/continue"
  Operation_members_list_continue.path = "/team/members/list/continue"
  Operation_members_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_list_continue.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_list_continue.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_list_continue.responses
}


// Operation: POST /sharing/list_received_files
// Returns a list of all files shared with current user.
// 
//      Does not include files the user has received via shared folders, and does
//      not include unclaimed invitations.
one sig Operation_list_received_files extends Operation {}

fact Operation_list_received_files_FieldValues {
  Operation_list_received_files.id = "list_received_files"
  Operation_list_received_files.path = "/sharing/list_received_files"
  Operation_list_received_files.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_received_files.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_received_files.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_received_files.responses
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
one sig Operation_docs_users_remove extends Operation {}

fact Operation_docs_users_remove_FieldValues {
  Operation_docs_users_remove.id = "docs/users/remove"
  Operation_docs_users_remove.path = "/paper/docs/users/remove"
  Operation_docs_users_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_users_remove.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_users_remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_users_remove.responses
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
one sig Operation_upload_session_finish extends Operation {}

fact Operation_upload_session_finish_FieldValues {
  Operation_upload_session_finish.id = "upload_session/finish"
  Operation_upload_session_finish.path = "/files/upload_session/finish"
  Operation_upload_session_finish.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_finish.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_finish.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session_finish.responses
}


// Operation: POST /files/copy_reference/save
// Save a copy reference returned by :route:`copy_reference/get` to the user's Dropbox.
one sig Operation_copy_reference_save extends Operation {}

fact Operation_copy_reference_save_FieldValues {
  Operation_copy_reference_save.id = "copy_reference/save"
  Operation_copy_reference_save.path = "/files/copy_reference/save"
  Operation_copy_reference_save.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_copy_reference_save.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_reference_save.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_reference_save.responses
}


// Operation: POST /team/properties/template/list
// Permission : Team member file access. The scope for the route is files.team_metadata.write.
one sig Operation_properties_template_list extends Operation {}

fact Operation_properties_template_list_FieldValues {
  Operation_properties_template_list.id = "properties/template/list"
  Operation_properties_template_list.path = "/team/properties/template/list"
  Operation_properties_template_list.method = "POST"
  // This operation has no request body
  no Operation_properties_template_list.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_list.responses
}


// Operation: POST /team/members/get_available_team_member_roles
// Get available TeamMemberRoles for the connected team. To be used with :route:`members/set_admin_permissions:2`.
// 
//     Permission : Team member management.
one sig Operation_members_get_available_team_member_roles extends Operation {}

fact Operation_members_get_available_team_member_roles_FieldValues {
  Operation_members_get_available_team_member_roles.id = "members/get_available_team_member_roles"
  Operation_members_get_available_team_member_roles.path = "/team/members/get_available_team_member_roles"
  Operation_members_get_available_team_member_roles.method = "POST"
  // This operation has no request body
  no Operation_members_get_available_team_member_roles.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_get_available_team_member_roles.responses
}


// Operation: POST /sharing/update_folder_member
// Allows an owner or editor of a shared folder to update another member's
//     permissions.
one sig Operation_update_folder_member extends Operation {}

fact Operation_update_folder_member_FieldValues {
  Operation_update_folder_member.id = "update_folder_member"
  Operation_update_folder_member.path = "/sharing/update_folder_member"
  Operation_update_folder_member.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_update_folder_member.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_folder_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_folder_member.responses
}


// Operation: POST /team/members/secondary_emails/resend_verification_emails
// Resend secondary email verification emails.
// 
//     Permission : Team member management.
one sig Operation_members_secondary_emails_resend_verification_emails extends Operation {}

fact Operation_members_secondary_emails_resend_verification_emails_FieldValues {
  Operation_members_secondary_emails_resend_verification_emails.id = "members/secondary_emails/resend_verification_emails"
  Operation_members_secondary_emails_resend_verification_emails.path = "/team/members/secondary_emails/resend_verification_emails"
  Operation_members_secondary_emails_resend_verification_emails.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_secondary_emails_resend_verification_emails.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_secondary_emails_resend_verification_emails.responses
}


// Operation: POST /team/groups/list
// Lists groups on a team.
// 
//     Permission : Team Information.
one sig Operation_groups_list extends Operation {}

fact Operation_groups_list_FieldValues {
  Operation_groups_list.id = "groups/list"
  Operation_groups_list.path = "/team/groups/list"
  Operation_groups_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_list.responses
}


// Operation: POST /sharing/relinquish_folder_membership
// The current user relinquishes their membership in the designated shared
//     folder and will no longer have access to the folder.  A folder owner cannot
//     relinquish membership in their own folder.
// 
//     This will run synchronously if leave_a_copy is false, and asynchronously
//     if leave_a_copy is true.
one sig Operation_relinquish_folder_membership extends Operation {}

fact Operation_relinquish_folder_membership_FieldValues {
  Operation_relinquish_folder_membership.id = "relinquish_folder_membership"
  Operation_relinquish_folder_membership.path = "/sharing/relinquish_folder_membership"
  Operation_relinquish_folder_membership.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_relinquish_folder_membership.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_relinquish_folder_membership.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_relinquish_folder_membership.responses
}


// Operation: POST /files/properties/template/list
// Execute properties/template/list
one sig Operation_properties_template_list extends Operation {}

fact Operation_properties_template_list_FieldValues {
  Operation_properties_template_list.id = "properties/template/list"
  Operation_properties_template_list.path = "/files/properties/template/list"
  Operation_properties_template_list.method = "POST"
  // This operation has no request body
  no Operation_properties_template_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_template_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_template_list.responses
}


// Operation: POST /team/team_folder/archive/check
// Returns the status of an asynchronous job for archiving a team folder.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_archive_check extends Operation {}

fact Operation_team_folder_archive_check_FieldValues {
  Operation_team_folder_archive_check.id = "team_folder/archive/check"
  Operation_team_folder_archive_check.path = "/team/team_folder/archive/check"
  Operation_team_folder_archive_check.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_archive_check.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_archive_check.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_archive_check.responses
}


// Operation: POST /team/members/set_admin_permissions
// Updates a team member's permissions.
// 
//     Permission : Team member management.
one sig Operation_members_set_admin_permissions extends Operation {}

fact Operation_members_set_admin_permissions_FieldValues {
  Operation_members_set_admin_permissions.id = "members/set_admin_permissions"
  Operation_members_set_admin_permissions.path = "/team/members/set_admin_permissions"
  Operation_members_set_admin_permissions.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_set_admin_permissions.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_set_admin_permissions.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_set_admin_permissions.responses
}


// Operation: POST /files/copy_batch:2
// Copy multiple files or folders to different locations at once in the
//     user's Dropbox.
// 
//     This route will return job ID immediately and do the async copy job in
//     background. Please use :route:`copy_batch/check:1` to check the job status.
one sig Operation_copy_batch_2 extends Operation {}

fact Operation_copy_batch_2_FieldValues {
  Operation_copy_batch_2.id = "copy_batch:2"
  Operation_copy_batch_2.path = "/files/copy_batch:2"
  Operation_copy_batch_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_copy_batch_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_batch_2.responses
}


// Operation: POST /files/copy_reference/get
// Get a copy reference to a file or folder. This reference string can be used to
//     save that file or folder to another user's Dropbox by passing it to
//     :route:`copy_reference/save`.
one sig Operation_copy_reference_get extends Operation {}

fact Operation_copy_reference_get_FieldValues {
  Operation_copy_reference_get.id = "copy_reference/get"
  Operation_copy_reference_get.path = "/files/copy_reference/get"
  Operation_copy_reference_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_copy_reference_get.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_copy_reference_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_copy_reference_get.responses
}


// Operation: POST /files/move_batch/check:2
// Returns the status of an asynchronous job for :route:`move_batch:1`. If
//     success, it returns list of results for each entry.
one sig Operation_move_batch_check_2 extends Operation {}

fact Operation_move_batch_check_2_FieldValues {
  Operation_move_batch_check_2.id = "move_batch/check:2"
  Operation_move_batch_check_2.path = "/files/move_batch/check:2"
  Operation_move_batch_check_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_move_batch_check_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_move_batch_check_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_move_batch_check_2.responses
}


// Operation: POST /files/download_zip
// Download a folder from the user's Dropbox, as a zip file. The folder must be less than 20 GB
//     in size and any single file within must be less than 4 GB in size. The resulting zip must have
//     fewer than 10,000 total file and folder entries, including the top level folder. The input
//     cannot be a single file.
// 
//     Note: this endpoint does not support HTTP range requests. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_download_zip extends Operation {}

fact Operation_download_zip_FieldValues {
  Operation_download_zip.id = "download_zip"
  Operation_download_zip.path = "/files/download_zip"
  Operation_download_zip.method = "POST"
  // This operation has no request body
  no Operation_download_zip.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_download_zip.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_download_zip.responses
}


// Operation: POST /sharing/remove_folder_member
// Allows an owner or editor (if the ACL update policy allows) of a shared
//     folder to remove another member.
one sig Operation_remove_folder_member extends Operation {}

fact Operation_remove_folder_member_FieldValues {
  Operation_remove_folder_member.id = "remove_folder_member"
  Operation_remove_folder_member.path = "/sharing/remove_folder_member"
  Operation_remove_folder_member.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_remove_folder_member.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_remove_folder_member.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_remove_folder_member.responses
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
one sig Operation_get_preview extends Operation {}

fact Operation_get_preview_FieldValues {
  Operation_get_preview.id = "get_preview"
  Operation_get_preview.path = "/files/get_preview"
  Operation_get_preview.method = "POST"
  // This operation has no request body
  no Operation_get_preview.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_preview.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_preview.responses
}


// Operation: POST /team/members/get_info
// Returns information about multiple team members.
// 
//     Permission : Team information
// 
//     This endpoint will return :field:`MembersGetInfoItem.id_not_found`,
//     for IDs (or emails) that cannot be matched to a valid team member.
one sig Operation_members_get_info extends Operation {}

fact Operation_members_get_info_FieldValues {
  Operation_members_get_info.id = "members/get_info"
  Operation_members_get_info.path = "/team/members/get_info"
  Operation_members_get_info.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_get_info.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_get_info.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_get_info.responses
}


// Operation: POST /team/groups/create
// Creates a new, empty group, with a requested name.
// 
//     Permission : Team member management.
one sig Operation_groups_create extends Operation {}

fact Operation_groups_create_FieldValues {
  Operation_groups_create.id = "groups/create"
  Operation_groups_create.path = "/team/groups/create"
  Operation_groups_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_create.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_create.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_create.responses
}


// Operation: POST /files/properties/remove
// Execute properties/remove
one sig Operation_properties_remove extends Operation {}

fact Operation_properties_remove_FieldValues {
  Operation_properties_remove.id = "properties/remove"
  Operation_properties_remove.path = "/files/properties/remove"
  Operation_properties_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_remove.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_remove.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_remove.responses
}


// Operation: POST /team/members/list:2
// Lists members of a team.
// 
//     Permission : Team information.
one sig Operation_members_list_2 extends Operation {}

fact Operation_members_list_2_FieldValues {
  Operation_members_list_2.id = "members/list:2"
  Operation_members_list_2.path = "/team/members/list:2"
  Operation_members_list_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_list_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_list_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_list_2.responses
}


// Operation: POST /team/members/send_welcome_email
// Sends welcome email to pending team member.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
// 
//     No-op if team member is not pending.
one sig Operation_members_send_welcome_email extends Operation {}

fact Operation_members_send_welcome_email_FieldValues {
  Operation_members_send_welcome_email.id = "members/send_welcome_email"
  Operation_members_send_welcome_email.path = "/team/members/send_welcome_email"
  Operation_members_send_welcome_email.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_send_welcome_email.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_send_welcome_email.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_send_welcome_email.responses
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
one sig Operation_docs_permanently_delete extends Operation {}

fact Operation_docs_permanently_delete_FieldValues {
  Operation_docs_permanently_delete.id = "docs/permanently_delete"
  Operation_docs_permanently_delete.path = "/paper/docs/permanently_delete"
  Operation_docs_permanently_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_permanently_delete.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_permanently_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_permanently_delete.responses
}


// Operation: POST /files/paper/create
// 
//     Creates a new Paper doc with the provided content.
//      Upload-style endpoint: Request has JSON parameters in Dropbox-API-Arg header and binary data in body. Response body is JSON.
one sig Operation_paper_create extends Operation {}

fact Operation_paper_create_FieldValues {
  Operation_paper_create.id = "paper/create"
  Operation_paper_create.path = "/files/paper/create"
  Operation_paper_create.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_paper_create.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_paper_create.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_paper_create.responses
}


// Operation: POST /team/groups/get_info
// Retrieves information about one or more groups. Note that the optional field
//      :field:`GroupFullInfo.members` is not returned for system-managed groups.
// 
//     Permission : Team Information.
one sig Operation_groups_get_info extends Operation {}

fact Operation_groups_get_info_FieldValues {
  Operation_groups_get_info.id = "groups/get_info"
  Operation_groups_get_info.path = "/team/groups/get_info"
  Operation_groups_get_info.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_get_info.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_get_info.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_get_info.responses
}


// Operation: POST /team/devices/list_members_devices
// List all device sessions of a team.
// 
//     Permission : Team member file access.
one sig Operation_devices_list_members_devices extends Operation {}

fact Operation_devices_list_members_devices_FieldValues {
  Operation_devices_list_members_devices.id = "devices/list_members_devices"
  Operation_devices_list_members_devices.path = "/team/devices/list_members_devices"
  Operation_devices_list_members_devices.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_devices_list_members_devices.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices_list_members_devices.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices_list_members_devices.responses
}


// Operation: POST /sharing/unshare_folder
// Allows a shared folder owner to unshare the folder.
// 
//     You'll need to call :route:`check_job_status` to determine if the action has
//     completed successfully.
one sig Operation_unshare_folder extends Operation {}

fact Operation_unshare_folder_FieldValues {
  Operation_unshare_folder.id = "unshare_folder"
  Operation_unshare_folder.path = "/sharing/unshare_folder"
  Operation_unshare_folder.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_unshare_folder.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_unshare_folder.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_unshare_folder.responses
}


// Operation: POST /team/team_folder/archive
// Sets an active team folder's status to archived and removes all folder and file members.
//     This endpoint cannot be used for teams that have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_archive extends Operation {}

fact Operation_team_folder_archive_FieldValues {
  Operation_team_folder_archive.id = "team_folder/archive"
  Operation_team_folder_archive.path = "/team/team_folder/archive"
  Operation_team_folder_archive.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_archive.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_archive.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_archive.responses
}


// Operation: POST /paper/docs/archive
// Marks the given Paper doc as archived.
// 
//     This action can be performed or undone by anyone with edit permissions to the doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     This endpoint will be retired in September 2020. Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for more information.
one sig Operation_docs_archive extends Operation {}

fact Operation_docs_archive_FieldValues {
  Operation_docs_archive.id = "docs/archive"
  Operation_docs_archive.path = "/paper/docs/archive"
  Operation_docs_archive.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_archive.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_archive.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_archive.responses
}


// Operation: POST /files/properties/overwrite
// Execute properties/overwrite
one sig Operation_properties_overwrite extends Operation {}

fact Operation_properties_overwrite_FieldValues {
  Operation_properties_overwrite.id = "properties/overwrite"
  Operation_properties_overwrite.path = "/files/properties/overwrite"
  Operation_properties_overwrite.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_overwrite.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_overwrite.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_overwrite.responses
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
one sig Operation_list_shared_links extends Operation {}

fact Operation_list_shared_links_FieldValues {
  Operation_list_shared_links.id = "list_shared_links"
  Operation_list_shared_links.path = "/sharing/list_shared_links"
  Operation_list_shared_links.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_shared_links.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_shared_links.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_shared_links.responses
}


// Operation: POST /files/lock_file_batch
// 
//     Lock the files at the given paths. A locked file will be writable only by the lock holder.
//     A successful response indicates that the file has been locked. Returns a list of the
//     locked file paths and their metadata after this operation.
//     
one sig Operation_lock_file_batch extends Operation {}

fact Operation_lock_file_batch_FieldValues {
  Operation_lock_file_batch.id = "lock_file_batch"
  Operation_lock_file_batch.path = "/files/lock_file_batch"
  Operation_lock_file_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_lock_file_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_lock_file_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_lock_file_batch.responses
}


// Operation: POST /team/members/get_info:2
// Returns information about multiple team members.
// 
//     Permission : Team information
// 
//     This endpoint will return :field:`MembersGetInfoItem.id_not_found`,
//     for IDs (or emails) that cannot be matched to a valid team member.
one sig Operation_members_get_info_2 extends Operation {}

fact Operation_members_get_info_2_FieldValues {
  Operation_members_get_info_2.id = "members/get_info:2"
  Operation_members_get_info_2.path = "/team/members/get_info:2"
  Operation_members_get_info_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_get_info_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_get_info_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_get_info_2.responses
}


// Operation: POST /team/member_space_limits/excluded_users/add
// Add users to member space limits excluded users list.
one sig Operation_member_space_limits_excluded_users_add extends Operation {}

fact Operation_member_space_limits_excluded_users_add_FieldValues {
  Operation_member_space_limits_excluded_users_add.id = "member_space_limits/excluded_users/add"
  Operation_member_space_limits_excluded_users_add.path = "/team/member_space_limits/excluded_users/add"
  Operation_member_space_limits_excluded_users_add.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_excluded_users_add.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_excluded_users_add.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_excluded_users_add.responses
}


// Operation: POST /files/download
// Download a file from a user's Dropbox. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_download extends Operation {}

fact Operation_download_FieldValues {
  Operation_download.id = "download"
  Operation_download.path = "/files/download"
  Operation_download.method = "POST"
  // This operation has no request body
  no Operation_download.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_download.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_download.responses
}


// Operation: POST /team/legal_holds/get_policy
// Gets a legal hold by Id.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_get_policy extends Operation {}

fact Operation_legal_holds_get_policy_FieldValues {
  Operation_legal_holds_get_policy.id = "legal_holds/get_policy"
  Operation_legal_holds_get_policy.path = "/team/legal_holds/get_policy"
  Operation_legal_holds_get_policy.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_get_policy.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_get_policy.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_get_policy.responses
}


// Operation: POST /file_properties/templates/update_for_team
// Update a template associated with a team. This route can update the template name,
//     the template description and add optional properties to templates.
one sig Operation_templates_update_for_team extends Operation {}

fact Operation_templates_update_for_team_FieldValues {
  Operation_templates_update_for_team.id = "templates/update_for_team"
  Operation_templates_update_for_team.path = "/file_properties/templates/update_for_team"
  Operation_templates_update_for_team.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_update_for_team.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_update_for_team.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_update_for_team.responses
}


// Operation: POST /team/members/list
// Lists members of a team.
// 
//     Permission : Team information.
one sig Operation_members_list extends Operation {}

fact Operation_members_list_FieldValues {
  Operation_members_list.id = "members/list"
  Operation_members_list.path = "/team/members/list"
  Operation_members_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_list.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_list.responses
}


// Operation: POST /file_properties/properties/update
// Add, update or remove properties associated with the supplied file and templates.
//     This endpoint should be used instead of :route:`properties/overwrite` when property groups
//     are being updated via a "delta" instead of via a "snapshot" . In other words, this endpoint
//     will not delete any omitted fields from a property group, whereas :route:`properties/overwrite`
//     will delete any fields that are omitted from a property group.
one sig Operation_properties_update extends Operation {}

fact Operation_properties_update_FieldValues {
  Operation_properties_update.id = "properties/update"
  Operation_properties_update.path = "/file_properties/properties/update"
  Operation_properties_update.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_update.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_update.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_update.responses
}


// Operation: POST /sharing/get_file_metadata/batch
// Returns shared file metadata.
one sig Operation_get_file_metadata_batch extends Operation {}

fact Operation_get_file_metadata_batch_FieldValues {
  Operation_get_file_metadata_batch.id = "get_file_metadata/batch"
  Operation_get_file_metadata_batch.path = "/sharing/get_file_metadata/batch"
  Operation_get_file_metadata_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_file_metadata_batch.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_file_metadata_batch.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_file_metadata_batch.responses
}


// Operation: POST /file_requests/list
// Returns a list of file requests owned by this user. For apps with the app
//     folder permission, this will only return file requests with destinations in
//     the app folder.
one sig Operation_list extends Operation {}

fact Operation_list_FieldValues {
  Operation_list.id = "list"
  Operation_list.path = "/file_requests/list"
  Operation_list.method = "POST"
  // This operation has no request body
  no Operation_list.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list.responses
}


// Operation: POST /users/get_account
// Get information about a user's account.
one sig Operation_get_account extends Operation {}

fact Operation_get_account_FieldValues {
  Operation_get_account.id = "get_account"
  Operation_get_account.path = "/users/get_account"
  Operation_get_account.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_account.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_account.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_account.responses
}


// Operation: POST /paper/docs/download
// Exports and downloads Paper doc either as HTML or markdown.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information. Download-style endpoint: Request has JSON parameters in Dropbox-API-Arg header. Response has JSON metadata in Dropbox-API-Result header and binary data in body.
one sig Operation_docs_download extends Operation {}

fact Operation_docs_download_FieldValues {
  Operation_docs_download.id = "docs/download"
  Operation_docs_download.path = "/paper/docs/download"
  Operation_docs_download.method = "POST"
  // This operation has no request body
  no Operation_docs_download.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_download.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_download.responses
}


// Operation: POST /sharing/set_access_inheritance
// Change the inheritance policy of an existing Shared Folder. Only permitted for shared folders in a shared team root.
// 
//     If a :field:`ShareFolderLaunch.async_job_id` is returned, you'll need to
//     call :route:`check_share_job_status` until the action completes to get the
//     metadata for the folder.
one sig Operation_set_access_inheritance extends Operation {}

fact Operation_set_access_inheritance_FieldValues {
  Operation_set_access_inheritance.id = "set_access_inheritance"
  Operation_set_access_inheritance.path = "/sharing/set_access_inheritance"
  Operation_set_access_inheritance.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_set_access_inheritance.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_set_access_inheritance.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_set_access_inheritance.responses
}


// Operation: POST /team/team_folder/permanently_delete
// Permanently deletes an archived team folder. This endpoint cannot be used for teams
//     that have a shared team space.
// 
//     Permission : Team member file access.
one sig Operation_team_folder_permanently_delete extends Operation {}

fact Operation_team_folder_permanently_delete_FieldValues {
  Operation_team_folder_permanently_delete.id = "team_folder/permanently_delete"
  Operation_team_folder_permanently_delete.path = "/team/team_folder/permanently_delete"
  Operation_team_folder_permanently_delete.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_team_folder_permanently_delete.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_team_folder_permanently_delete.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_team_folder_permanently_delete.responses
}


// Operation: POST /files/delete_batch
// Delete multiple files/folders at once.
// 
//     This route is asynchronous, which returns a job ID immediately and runs
//     the delete batch asynchronously. Use :route:`delete_batch/check` to check
//     the job status.
one sig Operation_delete_batch extends Operation {}

fact Operation_delete_batch_FieldValues {
  Operation_delete_batch.id = "delete_batch"
  Operation_delete_batch.path = "/files/delete_batch"
  Operation_delete_batch.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_delete_batch.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_batch.responses
}


// Operation: POST /contacts/delete_manual_contacts
// Removes all manually added contacts.
//     You'll still keep contacts who are on your team or who you imported.
//     New contacts will be added when you share.
one sig Operation_delete_manual_contacts extends Operation {}

fact Operation_delete_manual_contacts_FieldValues {
  Operation_delete_manual_contacts.id = "delete_manual_contacts"
  Operation_delete_manual_contacts.path = "/contacts/delete_manual_contacts"
  Operation_delete_manual_contacts.method = "POST"
  // This operation has no request body
  no Operation_delete_manual_contacts.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_manual_contacts.responses
}


// Operation: POST /file_properties/properties/overwrite
// Overwrite property groups associated with a file. This endpoint should be used
//     instead of :route:`properties/update` when property groups are being updated via a
//     "snapshot" instead of via a "delta". In other words, this endpoint will delete all
//     omitted fields from a property group, whereas :route:`properties/update` will only
//     delete fields that are explicitly marked for deletion.
one sig Operation_properties_overwrite extends Operation {}

fact Operation_properties_overwrite_FieldValues {
  Operation_properties_overwrite.id = "properties/overwrite"
  Operation_properties_overwrite.path = "/file_properties/properties/overwrite"
  Operation_properties_overwrite.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_properties_overwrite.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_properties_overwrite.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_properties_overwrite.responses
}


// Operation: POST /team/sharing_allowlist/remove
// Endpoint removes Approve List entries. Changes are effective immediately.
//     Changes are committed in transaction. In case of single validation error - all entries are rejected.
//     Valid domains (RFC-1034/5) and emails (RFC-5322/822) are accepted.
//     Entries being removed have to be present on the list.
//     Maximum 1000 entries per call is allowed.
one sig Operation_sharing_allowlist_remove extends Operation {}

fact Operation_sharing_allowlist_remove_FieldValues {
  Operation_sharing_allowlist_remove.id = "sharing_allowlist/remove"
  Operation_sharing_allowlist_remove.path = "/team/sharing_allowlist/remove"
  Operation_sharing_allowlist_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_sharing_allowlist_remove.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_sharing_allowlist_remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_sharing_allowlist_remove.responses
}


// Operation: POST /team/members/recover
// Recover a deleted member.
// 
//     Permission : Team member management
// 
//     Exactly one of team_member_id, email, or external_id must be provided to identify the user account.
one sig Operation_members_recover extends Operation {}

fact Operation_members_recover_FieldValues {
  Operation_members_recover.id = "members/recover"
  Operation_members_recover.path = "/team/members/recover"
  Operation_members_recover.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_recover.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_recover.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_recover.responses
}


// Operation: POST /files/tags/remove
// Remove a tag from an item.
one sig Operation_tags_remove extends Operation {}

fact Operation_tags_remove_FieldValues {
  Operation_tags_remove.id = "tags/remove"
  Operation_tags_remove.path = "/files/tags/remove"
  Operation_tags_remove.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_tags_remove.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags_remove.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags_remove.responses
}


// Operation: POST /team/legal_holds/list_policies
// Lists legal holds on a team.
//     Note: Legal Holds is a paid add-on. Not all teams have the feature.
// 
//     Permission : Team member file access.
one sig Operation_legal_holds_list_policies extends Operation {}

fact Operation_legal_holds_list_policies_FieldValues {
  Operation_legal_holds_list_policies.id = "legal_holds/list_policies"
  Operation_legal_holds_list_policies.path = "/team/legal_holds/list_policies"
  Operation_legal_holds_list_policies.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_legal_holds_list_policies.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_legal_holds_list_policies.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_legal_holds_list_policies.responses
}


// Operation: POST /files/get_temporary_link
// Get a temporary link to stream content of a file. This link will expire in four hours and
//     afterwards you will get 410 Gone. This URL should not be used to display content directly
//     in the browser. The Content-Type of the link is determined automatically by the file's mime type.
one sig Operation_get_temporary_link extends Operation {}

fact Operation_get_temporary_link_FieldValues {
  Operation_get_temporary_link.id = "get_temporary_link"
  Operation_get_temporary_link.path = "/files/get_temporary_link"
  Operation_get_temporary_link.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_get_temporary_link.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_get_temporary_link.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_get_temporary_link.responses
}


// Operation: POST /team/members/add/job_status/get
// Once an async_job_id is returned from :route:`members/add` ,
//     use this to poll the status of the asynchronous request.
// 
//     Permission : Team member management.
one sig Operation_members_add_job_status_get extends Operation {}

fact Operation_members_add_job_status_get_FieldValues {
  Operation_members_add_job_status_get.id = "members/add/job_status/get"
  Operation_members_add_job_status_get.path = "/team/members/add/job_status/get"
  Operation_members_add_job_status_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_add_job_status_get.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_add_job_status_get.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_add_job_status_get.responses
}


// Operation: POST /sharing/update_folder_policy
// Update the sharing policies for a shared folder.
// 
//     User must have :field:`AccessLevel.owner` access to the shared folder to update its policies.
one sig Operation_update_folder_policy extends Operation {}

fact Operation_update_folder_policy_FieldValues {
  Operation_update_folder_policy.id = "update_folder_policy"
  Operation_update_folder_policy.path = "/sharing/update_folder_policy"
  Operation_update_folder_policy.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_update_folder_policy.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_update_folder_policy.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_update_folder_policy.responses
}


// Operation: POST /files/search/continue:2
// Fetches the next page of search results returned from :route:`search:2`.
// 
//     Note: :route:`search:2` along with :route:`search/continue:2` can only be used to
//     retrieve a maximum of 10,000 matches.
// 
//     Recent changes may not immediately be reflected in search results due to a short delay in indexing.
//     Duplicate results may be returned across pages. Some results may not be returned.
one sig Operation_search_continue_2 extends Operation {}

fact Operation_search_continue_2_FieldValues {
  Operation_search_continue_2.id = "search/continue:2"
  Operation_search_continue_2.path = "/files/search/continue:2"
  Operation_search_continue_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_search_continue_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_search_continue_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_search_continue_2.responses
}


// Operation: POST /team/members/delete_profile_photo:2
// Deletes a team member's profile photo.
// 
//     Permission : Team member management.
one sig Operation_members_delete_profile_photo_2 extends Operation {}

fact Operation_members_delete_profile_photo_2_FieldValues {
  Operation_members_delete_profile_photo_2.id = "members/delete_profile_photo:2"
  Operation_members_delete_profile_photo_2.path = "/team/members/delete_profile_photo:2"
  Operation_members_delete_profile_photo_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_members_delete_profile_photo_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_members_delete_profile_photo_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_members_delete_profile_photo_2.responses
}


// Operation: POST /files/upload_session/finish_batch/check
// Returns the status of an asynchronous job for :route:`upload_session/finish_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_upload_session_finish_batch_check extends Operation {}

fact Operation_upload_session_finish_batch_check_FieldValues {
  Operation_upload_session_finish_batch_check.id = "upload_session/finish_batch/check"
  Operation_upload_session_finish_batch_check.path = "/files/upload_session/finish_batch/check"
  Operation_upload_session_finish_batch_check.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_finish_batch_check.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session_finish_batch_check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_finish_batch_check.responses
}


// Operation: POST /file_properties/templates/list_for_user
// Get the template identifiers for a team. To get the schema of
//     each template use :route:`templates/get_for_user`. This endpoint can't be
//     called on a team member or admin's behalf.
one sig Operation_templates_list_for_user extends Operation {}

fact Operation_templates_list_for_user_FieldValues {
  Operation_templates_list_for_user.id = "templates/list_for_user"
  Operation_templates_list_for_user.path = "/file_properties/templates/list_for_user"
  Operation_templates_list_for_user.method = "POST"
  // This operation has no request body
  no Operation_templates_list_for_user.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_list_for_user.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_list_for_user.responses
}


// Operation: POST /files/tags/get
// Get list of tags assigned to items.
one sig Operation_tags_get extends Operation {}

fact Operation_tags_get_FieldValues {
  Operation_tags_get.id = "tags/get"
  Operation_tags_get.path = "/files/tags/get"
  Operation_tags_get.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_tags_get.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_tags_get.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_tags_get.responses
}


// Operation: POST /sharing/revoke_shared_link
// Revoke a shared link.
// 
//     Note that even after revoking a shared link to a file, the file may be accessible if there are
//     shared links leading to any of the file parent folders. To list all shared links that enable
//     access to a specific file, you can use the :route:`list_shared_links` with the file as the
//     :field:`ListSharedLinksArg.path` argument.
one sig Operation_revoke_shared_link extends Operation {}

fact Operation_revoke_shared_link_FieldValues {
  Operation_revoke_shared_link.id = "revoke_shared_link"
  Operation_revoke_shared_link.path = "/sharing/revoke_shared_link"
  Operation_revoke_shared_link.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_revoke_shared_link.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_revoke_shared_link.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_revoke_shared_link.responses
}


// Operation: POST /team/member_space_limits/get_custom_quota
// Get users custom quota.
//     A maximum of 1000 members can be specified in a single call.
//     Note: to apply a custom space limit, a team admin needs to set a member space limit for the team first.
//     (the team admin can check the settings here: https://www.dropbox.com/team/admin/settings/space).
one sig Operation_member_space_limits_get_custom_quota extends Operation {}

fact Operation_member_space_limits_get_custom_quota_FieldValues {
  Operation_member_space_limits_get_custom_quota.id = "member_space_limits/get_custom_quota"
  Operation_member_space_limits_get_custom_quota.path = "/team/member_space_limits/get_custom_quota"
  Operation_member_space_limits_get_custom_quota.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_member_space_limits_get_custom_quota.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_member_space_limits_get_custom_quota.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_member_space_limits_get_custom_quota.responses
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
one sig Operation_upload_session_append_2 extends Operation {}

fact Operation_upload_session_append_2_FieldValues {
  Operation_upload_session_append_2.id = "upload_session/append:2"
  Operation_upload_session_append_2.path = "/files/upload_session/append:2"
  Operation_upload_session_append_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_upload_session_append_2.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_upload_session_append_2.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_upload_session_append_2.responses
}


// Operation: POST /files/search:2
// Searches for files and folders.
// 
//     Note: :route:`search:2` along with :route:`search/continue:2` can only be used to
//     retrieve a maximum of 10,000 matches.
// 
//     Recent changes may not immediately be reflected in search results due to a short delay in indexing.
//     Duplicate results may be returned across pages. Some results may not be returned.
one sig Operation_search_2 extends Operation {}

fact Operation_search_2_FieldValues {
  Operation_search_2.id = "search:2"
  Operation_search_2.path = "/files/search:2"
  Operation_search_2.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_search_2.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_search_2.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_search_2.responses
}


// Operation: POST /team/groups/members/list
// Lists members of a group.
// 
//     Permission : Team Information.
one sig Operation_groups_members_list extends Operation {}

fact Operation_groups_members_list_FieldValues {
  Operation_groups_members_list.id = "groups/members/list"
  Operation_groups_members_list.path = "/team/groups/members/list"
  Operation_groups_members_list.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_groups_members_list.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_groups_members_list.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_groups_members_list.responses
}


// Operation: POST /team/devices/list_member_devices
// List all device sessions of a team's member.
one sig Operation_devices_list_member_devices extends Operation {}

fact Operation_devices_list_member_devices_FieldValues {
  Operation_devices_list_member_devices.id = "devices/list_member_devices"
  Operation_devices_list_member_devices.path = "/team/devices/list_member_devices"
  Operation_devices_list_member_devices.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_devices_list_member_devices.request
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_devices_list_member_devices.responses
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_devices_list_member_devices.responses
}


// Operation: POST /users/features/get_values
// Get a list of feature values that may be configured for the current account.
one sig Operation_features_get_values extends Operation {}

fact Operation_features_get_values_FieldValues {
  Operation_features_get_values.id = "features/get_values"
  Operation_features_get_values.path = "/users/features/get_values"
  Operation_features_get_values.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_features_get_values.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_features_get_values.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_features_get_values.responses
}


// Operation: POST /sharing/list_file_members/continue
// Once a cursor has been retrieved from :route:`list_file_members` or
//     :route:`list_file_members/batch`, use this to paginate through all shared
//     file members.
one sig Operation_list_file_members_continue extends Operation {}

fact Operation_list_file_members_continue_FieldValues {
  Operation_list_file_members_continue.id = "list_file_members/continue"
  Operation_list_file_members_continue.path = "/sharing/list_file_members/continue"
  Operation_list_file_members_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_list_file_members_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_list_file_members_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_list_file_members_continue.responses
}


// Operation: POST /file_properties/templates/remove_for_user
// Permanently removes the specified template created from :route:`templates/add_for_user`.
//     All properties associated with the template will also be removed. This action
//     cannot be undone.
one sig Operation_templates_remove_for_user extends Operation {}

fact Operation_templates_remove_for_user_FieldValues {
  Operation_templates_remove_for_user.id = "templates/remove_for_user"
  Operation_templates_remove_for_user.path = "/file_properties/templates/remove_for_user"
  Operation_templates_remove_for_user.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_templates_remove_for_user.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_templates_remove_for_user.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_templates_remove_for_user.responses
}


// Operation: POST /paper/docs/list/continue
// Once a cursor has been retrieved from :route:`docs/list`, use this to
//     paginate through all Paper doc.
// 
//     Note that this endpoint will continue to work for content created by users on the older version of Paper. To check which version of Paper a user is on, use /users/features/get_values. If the paper_as_files feature is enabled, then the user is running the new version of Paper.
// 
//     Refer to the :link:`Paper Migration Guide https://www.dropbox.com/lp/developers/reference/paper-migration-guide` for migration information.
one sig Operation_docs_list_continue extends Operation {}

fact Operation_docs_list_continue_FieldValues {
  Operation_docs_list_continue.id = "docs/list/continue"
  Operation_docs_list_continue.path = "/paper/docs/list/continue"
  Operation_docs_list_continue.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_docs_list_continue.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_docs_list_continue.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_docs_list_continue.responses
}


// Operation: POST /sharing/add_file_member
// Adds specified members to a file.
one sig Operation_add_file_member extends Operation {}

fact Operation_add_file_member_FieldValues {
  Operation_add_file_member.id = "add_file_member"
  Operation_add_file_member.path = "/sharing/add_file_member"
  Operation_add_file_member.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_add_file_member.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_add_file_member.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_add_file_member.responses
}


// Operation: POST /files/delete_batch/check
// Returns the status of an asynchronous job for :route:`delete_batch`. If
//     success, it returns list of result for each entry.
one sig Operation_delete_batch_check extends Operation {}

fact Operation_delete_batch_check_FieldValues {
  Operation_delete_batch_check.id = "delete_batch/check"
  Operation_delete_batch_check.path = "/files/delete_batch/check"
  Operation_delete_batch_check.method = "POST"
  // This operation has a request body
  some req: Request | req in Operation_delete_batch_check.request
  // Response for status code: 400
  some r: Response | r.status = 400 and r in Operation_delete_batch_check.responses
  // Response for status code: 200
  some r: Response | r.status = 200 and r in Operation_delete_batch_check.responses
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
