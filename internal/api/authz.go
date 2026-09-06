package api

import (
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"go.kenn.io/msgvault/internal/authz"
)

// operationMinimumRole is the authorization policy of every /api/v1
// operation, keyed by OpenAPI operation ID. Reads are open to viewers,
// curation of the people graph and Saved Views to members, and everything
// that changes what the archive contains or how the daemon runs to admins.
// TestEveryAPIV1OperationIsClassified keeps this table complete: a new route
// without an entry fails closed at runtime and fails that test.
var operationMinimumRole = map[string]authz.Role{
	// System, health, identity of the caller, user administration.
	"getHealth":      authz.RoleViewer,
	"getMe":          authz.RoleViewer,
	"getStats":       authz.RoleViewer,
	"listUsers":      authz.RoleAdmin,
	"patchUser":      authz.RoleAdmin,
	"setUserSources": authz.RoleAdmin,

	// Sync scheduling and account registration.
	"listAccounts":         authz.RoleViewer,
	"addAccount":           authz.RoleAdmin,
	"uploadToken":          authz.RoleAdmin,
	"triggerSync":          authz.RoleAdmin,
	"getSchedulerStatus":   authz.RoleViewer,
	"listSourceStatus":     authz.RoleViewer,
	"listSourceIdentities": authz.RoleViewer,

	// Messages, conversations, attachments, files.
	"listMessages":            authz.RoleViewer,
	"listChangedMessages":     authz.RoleAdmin,
	"filterMessages":          authz.RoleViewer,
	"getGmailIDsByFilter":     authz.RoleViewer,
	"getMessage":              authz.RoleViewer,
	"getMessageInlinePart":    authz.RoleViewer,
	"listMessageTasks":        authz.RoleViewer,
	"createOrLinkMessageTask": authz.RoleMember,
	"unlinkMessageTask":       authz.RoleMember,
	"getConversation":         authz.RoleViewer,
	"getAttachment":           authz.RoleViewer,
	"getAttachmentContent":    authz.RoleViewer,
	"getFile":                 authz.RoleViewer,
	"getFileContent":          authz.RoleViewer,
	"searchFiles":             authz.RoleViewer,
	"groupFiles":              authz.RoleViewer,
	"getRemoteImage":          authz.RoleViewer,

	// Search, exploration, aggregates, analytics.
	"searchMessages":               authz.RoleViewer,
	"searchMessagesByDomains":      authz.RoleViewer,
	"fastSearch":                   authz.RoleViewer,
	"deepSearch":                   authz.RoleViewer,
	"findSimilarMessages":          authz.RoleViewer,
	"searchVisualAttachments":      authz.RoleViewer,
	"getSearchCoverage":            authz.RoleViewer,
	"searchDocuments":              authz.RoleViewer,
	"getDocumentIndexStatus":       authz.RoleViewer,
	"getDocumentVectorStatus":      authz.RoleViewer,
	"getAggregates":                authz.RoleViewer,
	"getSubAggregates":             authz.RoleViewer,
	"getTotalStats":                authz.RoleViewer,
	"explore":                      authz.RoleViewer,
	"exploreGroups":                authz.RoleViewer,
	"listExploreFiles":             authz.RoleViewer,
	"countExploreMatches":          authz.RoleViewer,
	"preflightExploreSelection":    authz.RoleViewer,
	"getTextAggregates":            authz.RoleViewer,
	"listTextConversations":        authz.RoleViewer,
	"listTextConversationMessages": authz.RoleViewer,
	"searchTextMessages":           authz.RoleViewer,
	"getTextStats":                 authz.RoleViewer,
	// Arbitrary read-only SQL over the whole archive cannot be scoped.
	"runQuery": authz.RoleAdmin,

	// Participants, domains, relationships.
	"searchParticipants":           authz.RoleViewer,
	"completeParticipants":         authz.RoleViewer,
	"getParticipant":               authz.RoleViewer,
	"listParticipantInboxes":       authz.RoleViewer,
	"searchParticipantFiles":       authz.RoleViewer,
	"getParticipantContextSummary": authz.RoleViewer,
	"getParticipantTimeline":       authz.RoleViewer,
	"searchDomains":                authz.RoleViewer,
	"getDomain":                    authz.RoleViewer,
	"searchDomainFiles":            authz.RoleViewer,
	"getDomainContextSummary":      authz.RoleViewer,
	"getDomainTimeline":            authz.RoleViewer,
	"listRelationships":            authz.RoleViewer,
	"getRelationshipCalendar":      authz.RoleViewer,
	"getRelationshipTimeline":      authz.RoleViewer,

	// People: reads for viewers, curation for members.
	"listPeople":                         authz.RoleViewer,
	"listDirectoryPeople":                authz.RoleViewer,
	"searchPeople":                       authz.RoleViewer,
	"createPerson":                       authz.RoleMember,
	"getPersonProfile":                   authz.RoleViewer,
	"patchPerson":                        authz.RoleMember,
	"deletePerson":                       authz.RoleMember,
	"listPersonAttributes":               authz.RoleViewer,
	"setPersonAttribute":                 authz.RoleMember,
	"clearPersonAttribute":               authz.RoleMember,
	"getPersonContactState":              authz.RoleViewer,
	"listPersonActivityDays":             authz.RoleViewer,
	"getPersonActivityDay":               authz.RoleViewer,
	"listPersonEmployments":              authz.RoleViewer,
	"listPersonFactClaims":               authz.RoleViewer,
	"listPersonFactDecisions":            authz.RoleViewer,
	"listPersonFactEvidence":             authz.RoleViewer,
	"listPersonFactEvidenceStatusEvents": authz.RoleViewer,
	"listPersonFactPins":                 authz.RoleViewer,
	"setPersonFactPin":                   authz.RoleMember,
	"listPersonFactTargets":              authz.RoleViewer,
	"searchPersonFiles":                  authz.RoleViewer,
	"mergePersons":                       authz.RoleMember,
	"listPersonMerges":                   authz.RoleViewer,
	"splitPersonMerge":                   authz.RoleMember,
	"getPersonMerge":                     authz.RoleViewer,
	"getPersonMergeSnapshot":             authz.RoleViewer,
	"decidePersonMergeCandidate":         authz.RoleMember,
	"getPersonNetwork":                   authz.RoleViewer,
	"appendPersonNote":                   authz.RoleMember,
	"getPersonStructuredProfile":         authz.RoleViewer,
	"patchPersonStructuredProfile":       authz.RoleMember,
	"getPersonProfileHistory":            authz.RoleViewer,
	"getPersonProfileMediaContent":       authz.RoleViewer,
	"listPersonRelationships":            authz.RoleViewer,
	"getPersonTracking":                  authz.RoleViewer,
	"setPersonTracking":                  authz.RoleMember,
	"listPersonRelationshipReviews":      authz.RoleViewer,
	"createPersonRelationship":           authz.RoleMember,
	"getPersonRelationship":              authz.RoleViewer,
	"patchPersonRelationship":            authz.RoleMember,
	"deletePersonRelationship":           authz.RoleMember,
	"listRelationshipTypes":              authz.RoleViewer,
	"createRelationshipType":             authz.RoleMember,
	"getRelationshipType":                authz.RoleViewer,
	"patchRelationshipType":              authz.RoleMember,
	"deleteRelationshipType":             authz.RoleMember,
	"linkIdentityParticipants":           authz.RoleMember,
	"unlinkIdentityParticipants":         authz.RoleMember,
	"listIdentityMatchCandidates":        authz.RoleViewer,
	"acceptIdentityMatchCandidate":       authz.RoleMember,
	"rejectIdentityMatchCandidate":       authz.RoleMember,

	// Organizations and employments.
	"listOrganizations":                  authz.RoleViewer,
	"createOrganization":                 authz.RoleMember,
	"getOrganization":                    authz.RoleViewer,
	"patchOrganization":                  authz.RoleMember,
	"deleteOrganization":                 authz.RoleMember,
	"listOrganizationAttributes":         authz.RoleViewer,
	"setOrganizationAttribute":           authz.RoleMember,
	"clearOrganizationAttribute":         authz.RoleMember,
	"listOrganizationEmployments":        authz.RoleViewer,
	"getOrganizationHistory":             authz.RoleViewer,
	"mergeOrganization":                  authz.RoleMember,
	"putOrganizationProfile":             authz.RoleMember,
	"getOrganizationProfileMediaContent": authz.RoleViewer,
	"createEmployment":                   authz.RoleMember,
	"getEmployment":                      authz.RoleViewer,
	"patchEmployment":                    authz.RoleMember,
	"deleteEmployment":                   authz.RoleMember,
	"endEmployment":                      authz.RoleMember,
	"setPrimaryEmployment":               authz.RoleMember,

	// Days and day entries.
	"getActivityDay": authz.RoleViewer,
	"listDayEntries": authz.RoleViewer,
	"createDayEntry": authz.RoleMember,
	"deleteDayEntry": authz.RoleMember,

	// Saved Views.
	"listSavedViews":  authz.RoleViewer,
	"getSavedView":    authz.RoleViewer,
	"createSavedView": authz.RoleMember,
	"patchSavedView":  authz.RoleMember,
	"deleteSavedView": authz.RoleMember,

	// Attribute vocabulary and communication services shape the archive.
	"listAttributeDefinitions":   authz.RoleViewer,
	"getAttributeDefinition":     authz.RoleViewer,
	"createAttributeDefinition":  authz.RoleAdmin,
	"patchAttributeDefinition":   authz.RoleAdmin,
	"deleteAttributeDefinition":  authz.RoleAdmin,
	"listCommunicationServices":  authz.RoleViewer,
	"createCommunicationService": authz.RoleAdmin,

	// Deletions, imports, backups, indexes, settings, integrations.
	"listDeletions":                       authz.RoleViewer,
	"getDeletion":                         authz.RoleViewer,
	"stageDeletion":                       authz.RoleAdmin,
	"cancelDeletion":                      authz.RoleAdmin,
	"createImportJob":                     authz.RoleAdmin,
	"getImportJob":                        authz.RoleViewer,
	"importMeeting":                       authz.RoleAdmin,
	"beginBackupFreeze":                   authz.RoleAdmin,
	"endBackupFreeze":                     authz.RoleAdmin,
	"getVisualAttachmentStatus":           authz.RoleViewer,
	"startVisualAttachmentBuild":          authz.RoleAdmin,
	"resumeVisualAttachmentBuild":         authz.RoleAdmin,
	"retryVisualAttachmentOwner":          authz.RoleAdmin,
	"retireVisualAttachmentGeneration":    authz.RoleAdmin,
	"listOperationRuns":                   authz.RoleViewer,
	"getOperationRun":                     authz.RoleViewer,
	"getOperationStatus":                  authz.RoleViewer,
	"getSettings":                         authz.RoleViewer,
	"patchSettings":                       authz.RoleAdmin,
	"putSettingsPersonEnrichmentProvider": authz.RoleAdmin,
	"putSettingsProviderCredential":       authz.RoleAdmin,
	"deleteSettingsProviderCredential":    authz.RoleAdmin,
	"getTaskIntegrationStatus":            authz.RoleViewer,
	"searchIntegrationTasks":              authz.RoleViewer,
	"testTaskIntegration":                 authz.RoleAdmin,

	// CardDAV publishes archive people to an external account.
	"getCardDAVStatus":       authz.RoleViewer,
	"listCardDAVBooks":       authz.RoleViewer,
	"listCardDAVConflicts":   authz.RoleViewer,
	"getCardDAVConflict":     authz.RoleViewer,
	"getCardDAVPublication":  authz.RoleViewer,
	"listCardDAVRuns":        authz.RoleViewer,
	"saveCardDAVAccount":     authz.RoleAdmin,
	"testCardDAVAccount":     authz.RoleAdmin,
	"updateCardDAVBookRoles": authz.RoleAdmin,
	"resolveCardDAVConflict": authz.RoleAdmin,
	"publishCardDAVPerson":   authz.RoleAdmin,
	"unpublishCardDAVPerson": authz.RoleAdmin,
	"syncCardDAV":            authz.RoleAdmin,

	// CLI transport: reads mirror the TUI, everything else is operational.
	"listCLIAccounts":            authz.RoleViewer,
	"getCLIStats":                authz.RoleViewer,
	"searchCLI":                  authz.RoleViewer,
	"getCLICacheStats":           authz.RoleViewer,
	"getCLICollection":           authz.RoleViewer,
	"listCLICollections":         authz.RoleViewer,
	"listCLIIdentities":          authz.RoleViewer,
	"getCLIMessage":              authz.RoleViewer,
	"getCLIMessageRaw":           authz.RoleViewer,
	"getCLIAttachment":           authz.RoleViewer,
	"updateCLIAccount":           authz.RoleAdmin,
	"planCLIAddCalendar":         authz.RoleAdmin,
	"buildCLICache":              authz.RoleAdmin,
	"createCLICollection":        authz.RoleAdmin,
	"deleteCLICollection":        authz.RoleAdmin,
	"addCLICollectionSources":    authz.RoleAdmin,
	"removeCLICollectionSources": authz.RoleAdmin,
	"planCLIDeduplicate":         authz.RoleAdmin,
	"planCLIDeleteDeduped":       authz.RoleAdmin,
	"executeCLIDeleteDeduped":    authz.RoleAdmin,
	"planCLIDeleteStaged":        authz.RoleAdmin,
	"createCLIDeletionManifest":  authz.RoleAdmin,
	"planCLIEmbeddings":          authz.RoleAdmin,
	"addCLIIdentity":             authz.RoleAdmin,
	"removeCLIIdentity":          authz.RoleAdmin,
	"discoverCLIIdentities":      authz.RoleAdmin,
	"importCLIIdentities":        authz.RoleAdmin,
	"initCLIArchive":             authz.RoleAdmin,
	"rebuildCLIFTS":              authz.RoleAdmin,
	"repairEncodingCLI":          authz.RoleAdmin,
	"repairMessageCLI":           authz.RoleAdmin,
	"runCLI":                     authz.RoleAdmin,
	"syncCLI":                    authz.RoleAdmin,
	"syncFullCLI":                authz.RoleAdmin,
	"verifyCLI":                  authz.RoleAdmin,
}

// minimumRoleForOperation returns the role an operation requires. An
// operation missing from the policy table fails closed to admin.
func minimumRoleForOperation(op *huma.Operation) authz.Role {
	if op != nil {
		if role, ok := operationMinimumRole[op.OperationID]; ok {
			return role
		}
	}
	return authz.RoleAdmin
}

func (s *Server) logForbiddenAPIRequest(r *http.Request, principal authz.Principal, required authz.Role) {
	if s.logger == nil {
		return
	}
	s.logger.Warn("forbidden API request",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("principal", string(principal.Kind)+":"+principal.Name),
		slog.String("role", string(principal.Role)),
		slog.String("required", string(required)),
		slog.String("remote", clientIP(r)),
	)
}
