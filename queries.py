from gql import gql

sbom_inventory = gql(
    """
    query (
        $first: Int
        $after: String
        $last: Int
        $before: String
        $page: Int
        $search: String
        $orgName: String
        $projectName: String
        $labelName: String
        $withVulnerabilities: Boolean
        $packageTypes: [String!]
        $isFixable: Boolean
        $withoutTransitiveThrough: Boolean
        $analysisId: String
        $orderBy: [PackagesOrder!]
        $locatePackageId: String
        $licenses: [String!]
    ) {
        packages(
            first: $first
            after: $after
            last: $last
            before: $before
            page: $page
            filters: {
                search: $search
                asset: {
                    organizationName: $orgName
                    projectName: $projectName
                    assetLabel: $labelName
                }
                analysisId: $analysisId
                withVulnerabilities: $withVulnerabilities
                packageTypes: $packageTypes
                isFixable: $isFixable
                withoutTransitiveThrough: $withoutTransitiveThrough
                licenses: $licenses
            }
            orderBy: $orderBy
            locatePackageId: $locatePackageId
        ) {
            totalCount
            edges {
                node {
                    packageId
                    name
                    version
                    packageType
                    ecosystem
                    analysisCount
                    vulnerabilities {
                        originalId
                        vulnerabilityId
                        originalId
                        severity
                        source {
                            name
                            url
                        }
                        description
                        ratings {
                            source {
                                name
                                url
                            }
                            score
                            severity
                            method
                            justification
                            vector
                        }
                        advisories {
                            title
                            url
                        }
                    }
                    vulnerabilityCount {
                        critical
                        high
                        medium
                        low
                        info
                        none
                        unknown
                    }
                    analysisCount
                    transitiveThrough {
                        name
                        version
                    }
                    licenses {
                        expression
                    }
                    scorecard {
                        date
                        checks {
                            name
                            score
                            documentationDesc
                            documentationUrl
                            reason
                            details
                        }
                        overallScore
                    }
                    scorecardUrl
                }
                cursor
            }
            filters {
                packageTypes {
                    value
                }
                licenses {
                    value
                }
            }
            pageInfo {
                hasNextPage
                hasPreviousPage
                startCursor
                endCursor
            }
        }
    }

    """
)

analytics_daily_metric = gql(
    """
query(
    $from_day: Date
    $to_day: Date
    $scannerIdsFilter: [String!]
    $assetIdsFilter: [String!]
    $max_rules: Int
    $bucket_size: BucketSize
    $search: String
    $isViolation: Boolean
    $policyIds: [String!]
){
    insights(
        fromDay: $from_day, 
        toDay: $to_day,
        maxRules: $max_rules,
        bucketSize: $bucket_size,
        filters: {
            scannerIds:$scannerIdsFilter
            assetIds:$assetIdsFilter
            search:$search
            isViolation: $isViolation
            policyIds: $policyIds
        }
    ) {
        dailyMetric {
            timeStamp,
            violations,
            findings,
            assets,
            scannerMetrics {
                scannerName
                violations
                findings
            }
        }
    }
}
"""
)

analytics_summary = gql(
    """
    query(
    $from_day: Date
    $to_day: Date
    $scannerIdsFilter: [String!]
    $assetIdsFilter: [String!]
    $max_rules: Int
    $bucket_size: BucketSize
    $search: String
    $isViolation: Boolean
    $policyIds: [String!]
){
    insights(
        fromDay: $from_day, 
        toDay: $to_day,
        maxRules: $max_rules,
        bucketSize: $bucket_size,
        filters: {
            scannerIds:$scannerIdsFilter
            assetIds:$assetIdsFilter
            search:$search
            isViolation: $isViolation
            policyIds: $policyIds
        }
    ) {
        summary {
            findings {
                previous
                current
            }
            violations {
                previous
                current
            }
            developerFixes {
                previous
                current
            }
            newViolations {
                previous
                current
            }
            fixes
            mergedViolations
        }
    }
}
"""
)

analytics_scan_metrics = gql(
    """
query (
    $assetId: String,
    $fromDate: Date,
    $toDate: Date,
    $policyIds: [String!]
  ) {
    scanMetrics(
      assetId: $assetId
      fromDate: $fromDate
      toDate: $toDate
      policyIds: $policyIds
    ) {
      totalScans
      totalFailedScans
    }
  }
"""
)

analytics_scans = gql(
    """
query (
  $first: Int,
  $after: String,
  $last: Int,
  $page: Int,
  $before: String,
  $assets: [String!]
  $assetTypes: [AssetTypeNameSchema!]
  $analyzers: [String!]
  $statuses: [StatusNameSchema!]
  $assetIds: [String!]
  $orderBy: [AnalysesOrder!]
  $fromDate: Date
  $toDate: Date
) { 
  analyses(
    first: $first
    after: $after
    last: $last
    before: $before
    page: $page
    filters: {
      assets: $assets
      assetTypes:$assetTypes
      analyzers:$analyzers
      statuses:$statuses
      assetIds:$assetIds
    }
    orderBy: $orderBy
    fromDate: $fromDate
    toDate: $toDate
  ) {
    filters {
      assets {
        value
        display
        count
      }
      assetTypes {
        count
        value
      }
      analyzers {
        count
        displayValue
        value
      }
      statuses {
        count
        value
      }
    }
    totalCount
    edges {
      node {
        policy { policyId name }
        analysisId
        accountId
        timestamp
        durationSeconds
        findingCount
        violationCount
        analyzerType
        analyzer {
          analyzerId
          analyzerName
        }
        resource {
          __typename
            ... on ScmOrganizationResource {
              resourceType
              resourceId
              scmProvider
              baseUrl
              organizationName
            }
            ... on ScmRepositoryResource {
              resourceType
              resourceId
              scmProvider
              baseUrl
              organizationName
              repositoryName
            }
            ... on ScmRepositoryCodeResource {
              resourceType
              resourceId
              scmProvider
              baseUrl
              organizationName
              repositoryName
              branchName
              commitId
              label
            }
            ... on ScmRepositoryCodeChangeResource {
              resourceType
              resourceId
              scmProvider
              baseUrl
              organizationName
              repositoryName
              branchName
              commitId
              pullRequestId
              label
            }
            ... on ContainerImageResource {
              resourceType
              resourceId
              containerRegistryProvider
              baseUrl
              registryName
              repositoryName
              label
              digest
              tags
            }
        }
        status {
          ...on Success {
            statusName
          }
          ...on Error {
            messages
            statusName
          }
          ...on Timeout {
            timeoutSeconds
            statusName
          }
          ...on BrokenInstallation {
            message
            statusName
          } 
        }
      }
      cursor
    }
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
  }
}
"""
)


get_accounts_query = gql(
    """
  query getAccounts {
  accounts {
    __typename
    ... on AuthOrganizationTypeSchema {
      orgId
      name
      displayName
      accountId
      __typename
    }
    ... on AuthErrorSchema {
      errorMessage
      __typename
    }
  }
}
"""
)

get_collections = gql(
    """
query getCollections($first: Int, $after: String, $last: Int, $before: String, $page: Int, $orderBy: [CollectionsOrderBy!], $filters: AssetManagementFilter) {
  assetManagement {
    collections(
      first: $first
      after: $after
      last: $last
      before: $before
      page: $page
      orderBy: $orderBy
      filters: $filters
    ) {
      pageInfo {
        ...PageInfoData
        __typename
      }
      totalCount
      totalOrphanCount
      edges {
        cursor
        node {
          ...CollectionData
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment PageInfoData on PageInfo {
  hasNextPage
  hasPreviousPage
  startCursor
  endCursor
  __typename
}

fragment CollectionData on Collection {
  id
  name
  iconUrl
  url
  provider
  isOrphan
  isManaged
  totalMonoreposCount
  resources {
    totalCount
    __typename
  }
  __typename
}
"""
)

get_collection_ids = gql(
    """
query getCollections($first: Int, $after: String, $last: Int, $before: String, $page: Int, $orderBy: [CollectionsOrderBy!], $filters: AssetManagementFilter) {
  assetManagement {
    collections(
      first: $first
      after: $after
      last: $last
      before: $before
      page: $page
      orderBy: $orderBy
      filters: $filters
    ) {
      pageInfo {
        ...PageInfoData
        __typename
      }
      totalCount
      totalOrphanCount
      edges {
        node {
          ...CollectionData
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment PageInfoData on PageInfo {
  hasNextPage
  hasPreviousPage
  startCursor
  endCursor
  __typename
}

fragment CollectionData on Collection {
  id
  name
}
"""
)

get_repository_ids = gql(
    """
query getCollection($collectionId: String!, $first: Int, $after: String, $last: Int, $before: String, $page: Int, $orderBy: [ResourcesOrderBy!], $filters: AssetManagementFilter, $scannerId: String) {
  collection(
    collectionId: $collectionId
    filters: $filters
    scannerId: $scannerId
  ) {
    ... on Collection {
      resources(
        first: $first
        after: $after
        last: $last
        before: $before
        page: $page
        orderBy: $orderBy
      ) {
        pageInfo {
          ...PageInfoData
          __typename
        }
        totalCount
        totalOrphanCount
        edges {
          cursor
          node {
            id
            name
            isOrphan
            isMonoRepo
            supportsMonoRepo
            isManaged(scannerId: $scannerId)
            subResources(scannerId: $scannerId) {
              edges {
                cursor
                node {
                  id
                  name
                  path
                  isOrphan
                  isEditable
                  __typename
                }
                __typename
              }
              pageInfo {
                ...PageInfoData
                __typename
              }
              totalCount
              __typename
            }
            __typename
          }
          __typename
        }
        __typename
      }
      __typename
    }
    ... on OperationError {
      errorMessage
      errorType
      __typename
    }
    __typename
  }
}

fragment PageInfoData on PageInfo {
  hasNextPage
  hasPreviousPage
  startCursor
  endCursor
  __typename
}
"""
)

get_resources = gql(
    """
query getResources($providerId: String!, $collectionId: String!, $filters: Filters, $first: Int, $after: String, $last: Int, $before: String, $page: Int) {
  provider(providerId: $providerId, filters: $filters) {
    collection(collectionId: $collectionId) {
      resources(
        first: $first
        after: $after
        last: $last
        before: $before
        page: $page
      ) {
        totalCount
        pageInfo {
          hasNextPage
          hasPreviousPage
          startCursor
          endCursor
          __typename
        }
        edges {
          cursor
          node {
            label
            resourceId
            assetType
            name
            policy {
              policyId
              name
              source
              assignment
              __typename
            }
            securityCoverage {
              category
              state
              activity
              __typename
            }
            scanners {
              scannerId
              name
              categories
              state
              activity
              provisioningMethod
              error {
                message
                __typename
              }
              ruleset {
                id
                name
                __typename
              }
              __typename
            }
            __typename
          }
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}
"""
)

get_security_posture_filters = gql(
    """
query getSecurityPostureFilters($filters: Filters) {
  securityPosture(filters: $filters) {
    filters {
      needsAttention {
        ...BasicFilterCount
        __typename
      }
      resourceProvisioningStatus {
        ...BasicFilterCount
        __typename
      }
      collection {
        ...CollectionFilter
        __typename
      }
      missingCoverage {
        ...BasicFilterCount
        __typename
      }
      resourceAttribute {
        ...BasicFilterCount
        __typename
      }
      policy {
        ...PolicyFilter
        __typename
      }
      policyType {
        ...BasicFilterCount
        __typename
      }
      provisionedAnalyzer {
        ...ProvisionedAnalyzerFilter
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment BasicFilterCount on BasicFilterCount {
  value
  count
  __typename
}

fragment CollectionFilter on CollectionFilterDisplayFilterCountWithDisplay {
  value
  count
  display {
    name
    provider
    __typename
  }
  __typename
}

fragment PolicyFilter on PolicyFilterDisplayFilterCountWithDisplay {
  value
  count
  display {
    name
    __typename
  }
  __typename
}

fragment ProvisionedAnalyzerFilter on ProvisionedAnalyzerFilterCount {
  value
  count
  display {
    analyzerId
    analyzerName
    rulesetName
    __typename
  }
  __typename
}
"""
)

get_group_findings = gql(
    """
query getGroupFindings($filters: FindingGroupFiltersSchema, $first: Int, $after: String, $last: Int, $before: String, $page: Int, $locateId: String, $aggregation: AggregationInput, $orderBy: [GroupsOrderBy!]) {
  groups(
    filters: $filters
    first: $first
    after: $after
    last: $last
    before: $before
    page: $page
    locateId: $locateId
    aggregation: $aggregation
    orderBy: $orderBy
  ) {
    totalCount
    page
    locatedFindingGroupId
    edges {
      node {
        findingGroupId
        findingsCount
        isViolation
        ruleDescription
        ruleName
        uri
        asset {
          organizationName
          projectName
          label
          viewerAssetId
          scmProvider
          baseUrl
          repositoryAttributes {
            personalInformationCategories {
              value
              displayValue
              __typename
            }
            applicationComposition {
              value
              displayValue
              __typename
            }
            access {
              value
              displayValue
              __typename
            }
            contributors {
              name
              link
              __typename
            }
            associatedServices {
              value
              displayValue
              __typename
            }
            __typename
          }
          __typename
        }
        resource {
          resourceId
          resourceType
          ... on ScmOrganizationResource {
            scmProvider
            baseUrl
            organizationName
            __typename
          }
          ... on ScmRepositoryResource {
            scmProvider
            baseUrl
            organizationName
            repositoryName
            __typename
          }
          ... on ScmRepositoryCodeResource {
            scmProvider
            baseUrl
            organizationName
            repositoryName
            label
            branchName
            commitId
            __typename
          }
          ... on ScmRepositoryCodeChangeResource {
            scmProvider
            baseUrl
            organizationName
            repositoryName
            label
            branchName
            commitId
            pullRequestId
            __typename
          }
          ... on ContainerImageResource {
            containerRegistryProvider
            baseUrl
            registryName
            repositoryName
            label
            digest
            tags
            __typename
          }
          __typename
        }
        scanners {
          scannerId
          scannerName
          __typename
        }
        suppressions {
          suppressionTagId
          suppressionType
          justification
          mutable
          isGroupSuppression
          until
          author
          duration
          __typename
        }
        scmLink {
          text
          href
          __typename
        }
        severity
        confidence
        categories {
          name
          prettyName
          ref
          __typename
        }
        descriptionContent {
          contentType
          content
          __typename
        }
        prettyRuleName
        prettyDescription
        docRef
        details {
          __typename
          ... on SastDetails {
            fileLocation {
              uri
              scmVersioned
              startLineNumber
              startColumnNumber
              endLineNumber
              endColumnNumber
              __typename
            }
            commitId
            __typename
          }
          ... on ScaDetails {
            dependencyScope
            licenses
            package {
              name
              ecosystem
              __typename
            }
            requirement
            manifestFileLocation {
              uri
              scmVersioned
              startLineNumber
              startColumnNumber
              endLineNumber
              endColumnNumber
              __typename
            }
            impactedVersions
            cvssScore
            epssScore
            advisoryLink
            cve
            cvePublishedDate
            transitiveInfo {
              name
              version
              __typename
            }
            cveSummary
            fixedVersions
            fixableStatus
            scorecard
            reachability
            __typename
          }
          ... on CicdDetails {
            repositoryName
            __typename
          }
          ... on ContainerScanningDetails {
            dependencyScope
            licenses
            vulnerabilityId
            imageName
            imageVersion
            tags
            layerId
            requirement
            impactedVersions
            cvssScore
            epssScore
            advisoryLink
            package {
              name
              ecosystem
              __typename
            }
            cvePublishedDate
            transitiveInfo {
              name
              version
              __typename
            }
            cveSummary
            fixedVersions
            fixableStatus
            scorecard
            __typename
          }
        }
        originalRuleId
        vulnerabilityIdentifiers {
          value
          identifierType
          __typename
        }
        timestamp
        acknowledgement
        policy {
          policyId
          policyName
          version
          __typename
        }
        __typename
      }
      cursor
      __typename
    }
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
      __typename
    }
    __typename
  }
}
"""
)


get_security_posture_attributes = gql("""
  query getSecurityPostureFilters($filters: Filters) {
  securityPosture(filters: $filters) {
    filters {
      resourceAttribute {
        ...BasicFilterCount
        __typename
      }
    }
    __typename
  }
}

fragment BasicFilterCount on BasicFilterCount {
  value
  count
  __typename
}
""")
