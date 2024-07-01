from gql import gql


create_token = gql(
    """
mutation createActAsToken($organizationId: String!, $accountId: String!, $features: [String!]) {
  createActAsToken(
    orgId: $organizationId
    accountId: $accountId
    features: $features
  ) {
    token
    __typename
  }
}
"""
)

apply_provision_plan = gql(
    """
mutation applyProvisionPlan($assetSelection: [AssetSelection!]!, $scanners: [ScannerOperation!], $policy: PolicyOperation, $removeDeprovisionedData: Boolean) {
  applyProvisionPlan(
    assetSelections: $assetSelection
    scanners: $scanners
    policy: $policy
    removeDeprovisionedData: $removeDeprovisionedData
  ) {
    ... on OperationError {
      __typename
      errorMessage
      errorType
    }
    ... on OperationSuccess {
      __typename
    }
    __typename
  }
}
"""
)
