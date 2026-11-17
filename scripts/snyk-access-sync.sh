#!/usr/bin/env bash
#
# Reads a repository access file (.github/snyk-access.yaml) and adds the
# listed users to the Snyk Organization that the repository maps to.
#
# Modes:
#   validate  Check the file only. Makes no Snyk API calls and needs no token.
#   dry-run   Validate, resolve the Snyk Organization and users, and report
#             what would change. Makes no membership changes.
#   apply     Validate, resolve, and create the missing Org Memberships.
#
# The script only adds memberships. It never removes a user or changes the
# role of an existing member.

set -euo pipefail

ACCESS_FILE="${ACCESS_FILE:-.github/snyk-access.yaml}"
MODE="${MODE:-apply}"
SNYK_API_URL="${SNYK_API_URL:-https://api.snyk.io}"
SNYK_API_VERSION="${SNYK_API_VERSION:-2025-11-05}"
SNYK_ASSETS_API_VERSION="${SNYK_ASSETS_API_VERSION:-$SNYK_API_VERSION}"
SNYK_RETRY_DELAY="${SNYK_RETRY_DELAY:-2}"
FAIL_ON_UNRESOLVED="${FAIL_ON_UNRESOLVED:-false}"
REPO_URL="${REPO_URL:-}"
GIT_REF="${GIT_REF:-}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-}"
SUPPORTED_VERSIONS='[1]'

HTTP_STATUS=""
HTTP_BODY=""

log() { printf '%s\n' "$*" >&2; }
error() { printf '::error::%s\n' "$*" >&2; }
die() {
  error "$*"
  exit 1
}

require_env() {
  local name
  for name in "$@"; do
    [[ -n "${!name:-}" ]] || die "$name is required in $MODE mode."
  done
}

summary() {
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$*" >>"$GITHUB_STEP_SUMMARY"
  else
    printf '%s\n' "$*"
  fi
}

set_output() {
  [[ -n "${GITHUB_OUTPUT:-}" ]] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  return 0
}

# Sends a request to the Snyk API and stores the result in HTTP_STATUS and
# HTTP_BODY. Retries on rate limiting, server errors, and network errors.
# The token goes through a curl config on a file descriptor so that it never
# appears in the process list.
snyk_request() {
  local method=$1 url=$2 body=${3:-} content_type=${4:-application/vnd.api+json}
  local attempt=1 out
  out=$(mktemp)
  while :; do
    local args=(-sS -o "$out" -w '%{http_code}' -X "$method"
      -H 'Accept: application/vnd.api+json, application/json')
    if [[ -n "$body" ]]; then
      args+=(-H "Content-Type: $content_type" --data "$body")
    fi
    HTTP_STATUS=$(curl -K <(printf 'header = "Authorization: token %s"\n' "$SNYK_TOKEN") \
      "${args[@]}" "$url") || HTTP_STATUS=000
    if [[ "$HTTP_STATUS" == 429 || "$HTTP_STATUS" == 5* || "$HTTP_STATUS" == 000 ]] && ((attempt < 4)); then
      log "Snyk API returned $HTTP_STATUS for $method $url. Retrying ($attempt/3)."
      sleep $((attempt * SNYK_RETRY_DELAY))
      attempt=$((attempt + 1))
      continue
    fi
    break
  done
  HTTP_BODY=$(cat "$out")
  rm -f "$out"
}

rest_url() {
  local path=$1 version=${2:-$SNYK_API_VERSION} sep='?'
  [[ "$path" == *\?* ]] && sep='&'
  printf '%s/rest%s%sversion=%s' "$SNYK_API_URL" "$path" "$sep" "$version"
}

api_error_detail() {
  jq -r '[.errors[]? | .detail // .title] | first // empty' <<<"$HTTP_BODY" 2>/dev/null || true
}

# --- Static validation -------------------------------------------------------

[[ "$MODE" =~ ^(validate|dry-run|apply)$ ]] || die "MODE must be validate, dry-run, or apply. Got: $MODE"
[[ -f "$ACCESS_FILE" ]] || die "Access file not found: $ACCESS_FILE"

if ! DOCUMENTS=$(yq ea -o=json -I=0 '[.]' "$ACCESS_FILE" 2>&1); then
  die "$ACCESS_FILE is not valid YAML: $DOCUMENTS"
fi
[[ $(jq 'length' <<<"$DOCUMENTS") == 1 ]] || die "$ACCESS_FILE must contain exactly one YAML document."
ACCESS_JSON=$(jq -c '.[0]' <<<"$DOCUMENTS")

VALIDATION_ERRORS=$(jq -r --argjson supported "$SUPPORTED_VERSIONS" '
  def uuid: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
  def is_email: type == "string" and test("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
  def entry_errors($list):
    if (.[$list] | type) != "array" then empty else
      .[$list] | to_entries[] | .key as $i | .value |
      if type != "object" then "\($list)[\($i)] must be a mapping with an email key."
      else
        ((keys - ["email"])[] | "\($list)[\($i)] has unsupported key \"\(.)\". Roles are fixed by list and cannot be set per user."),
        (if (.email | is_email) then empty else "\($list)[\($i)].email must be an email address." end)
      end
    end;

  if type != "object" then "The file must be a YAML mapping."
  else
    ((keys - ["version", "organization", "org_admins", "users"])[] | "Unknown top-level key \"\(.)\"."),

    (if .version == null then "version is required."
     elif (.version as $v | $supported | index($v)) == null then "Unsupported version \(.version). Supported versions: \($supported | join(", "))."
     else empty end),

    (if .organization == null then empty
     elif (.organization | type) != "object" then "organization must be a mapping."
     else
       ((.organization | keys - ["id"])[] | "Unknown key \"\(.)\" under organization."),
       (if .organization.id == null then empty
        elif (.organization.id | type) == "string" and (.organization.id | test(uuid)) then empty
        else "organization.id must be a Snyk Organization ID (UUID)." end)
     end),

    (if (.org_admins | type) != "array" or (.org_admins | length) == 0
     then "org_admins must be a list with at least one entry." else empty end),

    (if .users == null or (.users | type) == "array" then empty else "users must be a list." end),

    entry_errors("org_admins"),
    entry_errors("users"),

    ([(.org_admins // [] | if type == "array" then .[] else empty end),
      (.users // [] | if type == "array" then .[] else empty end)]
     | map(select(type == "object" and (.email | type) == "string") | .email | ascii_downcase)
     | group_by(.) | map(select(length > 1) | .[0])[]
     | "\(.) appears more than once across org_admins and users.")
  end
' <<<"$ACCESS_JSON")

if [[ -n "$VALIDATION_ERRORS" ]]; then
  summary "## Snyk access: validation failed"
  summary ""
  summary "\`$ACCESS_FILE\` has the following problems. No membership changes were made."
  summary ""
  while IFS= read -r line; do
    error "$ACCESS_FILE: $line"
    summary "- $line"
  done <<<"$VALIDATION_ERRORS"
  exit 1
fi

MEMBERS=$(jq -c '
  [(.org_admins[] | {email, role: "org_admin"}),
   ((.users // [])[] | {email, role: "developer"})]' <<<"$ACCESS_JSON")
FILE_ORG_ID=$(jq -r '.organization.id // empty' <<<"$ACCESS_JSON")

log "$ACCESS_FILE is valid. Org Admins: $(jq 'map(select(.role == "org_admin")) | length' <<<"$MEMBERS"). Users: $(jq 'map(select(.role == "developer")) | length' <<<"$MEMBERS")."

if [[ "$MODE" == validate ]]; then
  summary "## Snyk access: validation passed"
  summary ""
  summary "\`$ACCESS_FILE\` is valid and lists $(jq 'length' <<<"$MEMBERS") emails. Membership changes run after the pull request merges to the default branch."
  exit 0
fi

# --- Remote validation -------------------------------------------------------

require_env SNYK_TOKEN SNYK_GROUP_ID SNYK_ORG_ADMIN_ROLE_ID SNYK_DEVELOPER_ROLE_ID

if [[ "$MODE" == apply && -n "$GIT_REF" && -n "$DEFAULT_BRANCH" && "$GIT_REF" != "refs/heads/$DEFAULT_BRANCH" ]]; then
  die "apply mode only runs from the default branch ($DEFAULT_BRANCH). Current ref: $GIT_REF"
fi

REMOTE_ERRORS=""
remote_error() { REMOTE_ERRORS+="$1"$'\n'; }

snyk_request GET "$SNYK_API_URL/v1/group/$SNYK_GROUP_ID/roles"
if [[ "$HTTP_STATUS" != 200 ]]; then
  die "Could not list the roles in Snyk Group $SNYK_GROUP_ID (HTTP $HTTP_STATUS). $(api_error_detail)"
fi
GROUP_ROLES="$HTTP_BODY"
role_name() { jq -r --arg id "$1" 'map(select(.publicId == $id)) | first | .name // empty' <<<"$GROUP_ROLES"; }
ORG_ADMIN_ROLE_NAME=$(role_name "$SNYK_ORG_ADMIN_ROLE_ID")
DEVELOPER_ROLE_NAME=$(role_name "$SNYK_DEVELOPER_ROLE_ID")
[[ -n "$ORG_ADMIN_ROLE_NAME" ]] || remote_error "The Org Admin role $SNYK_ORG_ADMIN_ROLE_ID does not exist in the Snyk Group."
[[ -n "$DEVELOPER_ROLE_NAME" ]] || remote_error "The developer role $SNYK_DEVELOPER_ROLE_ID does not exist in the Snyk Group."

ORG_ID=""
ORG_SOURCE=""
if [[ -n "$FILE_ORG_ID" ]]; then
  ORG_ID="$FILE_ORG_ID"
  ORG_SOURCE="organization.id"
else
  [[ -n "$REPO_URL" ]] || die "REPO_URL is required when organization.id is not set."
  NORMALIZED_REPO_URL=$(printf '%s' "$REPO_URL" | sed -E 's#/+$##; s#\.git$##')
  SEARCH_BODY=$(jq -cn --arg url "$NORMALIZED_REPO_URL" \
    '{query: {attributes: {attribute: "repository_url", operator: "equal", values: [$url]}}}')
  snyk_request POST "$(rest_url "/groups/$SNYK_GROUP_ID/assets/search?limit=100" "$SNYK_ASSETS_API_VERSION")" \
    "$SEARCH_BODY" application/json
  if [[ "$HTTP_STATUS" != 200 ]]; then
    die "Asset search for $NORMALIZED_REPO_URL failed (HTTP $HTTP_STATUS). $(api_error_detail)"
  fi
  ORG_IDS=$(jq -c '[.data[]? | select(.type == "repository")
    | .relationships.organizations.data[]?.id] | unique' <<<"$HTTP_BODY")
  case $(jq 'length' <<<"$ORG_IDS") in
    0) remote_error "No Snyk Organization is linked to $NORMALIZED_REPO_URL. Import the repository into Snyk or set organization.id." ;;
    1)
      ORG_ID=$(jq -r '.[0]' <<<"$ORG_IDS")
      ORG_SOURCE="Asset Search ($NORMALIZED_REPO_URL)"
      ;;
    *) remote_error "$NORMALIZED_REPO_URL is linked to several Snyk Organizations ($(jq -r 'join(", ")' <<<"$ORG_IDS")). Set organization.id to choose one." ;;
  esac
fi

ORG_NAME=""
if [[ -n "$ORG_ID" ]]; then
  snyk_request GET "$(rest_url "/orgs/$ORG_ID")"
  if [[ "$HTTP_STATUS" == 200 ]]; then
    ORG_GROUP_ID=$(jq -r '.data.attributes.group_id // empty' <<<"$HTTP_BODY")
    ORG_NAME=$(jq -r '.data.attributes.name // empty' <<<"$HTTP_BODY")
    if [[ "$ORG_GROUP_ID" != "$SNYK_GROUP_ID" ]]; then
      remote_error "Snyk Organization $ORG_ID does not belong to Snyk Group $SNYK_GROUP_ID."
    fi
  else
    remote_error "Could not read Snyk Organization $ORG_ID (HTTP $HTTP_STATUS). $(api_error_detail)"
  fi
fi

if [[ -n "$REMOTE_ERRORS" ]]; then
  summary "## Snyk access: validation failed"
  summary ""
  summary "No membership changes were made."
  summary ""
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    error "$line"
    summary "- $line"
  done <<<"$REMOTE_ERRORS"
  exit 1
fi

set_output org-id "$ORG_ID"
log "Snyk Organization: ${ORG_NAME:-$ORG_ID} ($ORG_ID), from $ORG_SOURCE."

# --- Resolve user IDs --------------------------------------------------------
# All lookups finish before any membership is created, so a lookup failure
# leaves the Snyk Organization unchanged.

RESOLVED='[]'
UNRESOLVED='[]'
COUNT=$(jq 'length' <<<"$MEMBERS")
for ((i = 0; i < COUNT; i++)); do
  MEMBER=$(jq -c ".[$i]" <<<"$MEMBERS")
  EMAIL=$(jq -r '.email' <<<"$MEMBER")
  ENCODED_EMAIL=$(jq -rn --arg e "$EMAIL" '$e | @uri')
  snyk_request GET "$(rest_url "/groups/$SNYK_GROUP_ID/memberships?email=$ENCODED_EMAIL&limit=100")"
  if [[ "$HTTP_STATUS" != 200 ]]; then
    die "Could not look up $EMAIL in the Snyk Group (HTTP $HTTP_STATUS). $(api_error_detail) No membership changes were made."
  fi
  USER_ID=$(jq -r --arg e "$EMAIL" '
    [.data[]? | .relationships.user.data
     | select((.attributes.email // "" | ascii_downcase) == ($e | ascii_downcase)) | .id]
    | first // empty' <<<"$HTTP_BODY")
  if [[ -n "$USER_ID" ]]; then
    RESOLVED=$(jq -c --argjson m "$MEMBER" --arg id "$USER_ID" '. + [$m + {user_id: $id}]' <<<"$RESOLVED")
  else
    UNRESOLVED=$(jq -c --argjson m "$MEMBER" '. + [$m]' <<<"$UNRESOLVED")
  fi
done

# --- Create memberships ------------------------------------------------------

RESULTS='[]'
record() {
  RESULTS=$(jq -c --argjson m "$1" --arg outcome "$2" --arg detail "${3:-}" \
    '. + [$m + {outcome: $outcome, detail: $detail}]' <<<"$RESULTS")
}

COUNT=$(jq 'length' <<<"$RESOLVED")
for ((i = 0; i < COUNT; i++)); do
  MEMBER=$(jq -c ".[$i]" <<<"$RESOLVED")
  EMAIL=$(jq -r '.email' <<<"$MEMBER")
  USER_ID=$(jq -r '.user_id' <<<"$MEMBER")
  if [[ $(jq -r '.role' <<<"$MEMBER") == org_admin ]]; then
    ROLE_ID="$SNYK_ORG_ADMIN_ROLE_ID"
  else
    ROLE_ID="$SNYK_DEVELOPER_ROLE_ID"
  fi

  snyk_request GET "$(rest_url "/orgs/$ORG_ID/memberships?user_id=$USER_ID&limit=100")"
  if [[ "$HTTP_STATUS" != 200 ]]; then
    record "$MEMBER" failed "Could not read the existing membership (HTTP $HTTP_STATUS). $(api_error_detail)"
    continue
  fi
  CURRENT_ROLE=$(jq -c --arg id "$USER_ID" '
    [.data[]? | select(.relationships.user.data.id == $id) | .relationships.role.data]
    | first // empty' <<<"$HTTP_BODY")
  if [[ -n "$CURRENT_ROLE" ]]; then
    if [[ $(jq -r '.id' <<<"$CURRENT_ROLE") == "$ROLE_ID" ]]; then
      record "$MEMBER" already_member
    else
      record "$MEMBER" different_role "Holds the $(jq -r '.attributes.name // .id' <<<"$CURRENT_ROLE") role. Not changed."
    fi
    continue
  fi

  if [[ "$MODE" == dry-run ]]; then
    record "$MEMBER" would_add
    continue
  fi

  CREATE_BODY=$(jq -cn --arg org "$ORG_ID" --arg role "$ROLE_ID" --arg user "$USER_ID" '{
    data: {
      type: "org_membership",
      relationships: {
        org: {data: {type: "org", id: $org}},
        role: {data: {type: "org_role", id: $role}},
        user: {data: {type: "user", id: $user}}
      }
    }}')
  snyk_request POST "$(rest_url "/orgs/$ORG_ID/memberships")" "$CREATE_BODY"
  case "$HTTP_STATUS" in
    201) record "$MEMBER" added ;;
    409) record "$MEMBER" already_member "The Snyk API reported an existing membership." ;;
    *) record "$MEMBER" failed "HTTP $HTTP_STATUS. $(api_error_detail)" ;;
  esac
done

# --- Report ------------------------------------------------------------------

count_outcome() { jq --arg o "$1" 'map(select(.outcome == $o)) | length' <<<"$RESULTS"; }
ADDED=$(count_outcome added)
WOULD_ADD=$(count_outcome would_add)
FAILED=$(count_outcome failed)
UNRESOLVED_COUNT=$(jq 'length' <<<"$UNRESOLVED")

set_output added-count "$ADDED"
set_output failed-count "$FAILED"
set_output unresolved-count "$UNRESOLVED_COUNT"

ROLE_LABELS=$(jq -cn --arg a "$ORG_ADMIN_ROLE_NAME" --arg d "$DEVELOPER_ROLE_NAME" '{org_admin: $a, developer: $d}')
OUTCOME_LABELS='{"added":"Added","would_add":"Would add (dry run)","already_member":"Skipped: already has this role","different_role":"Skipped: has a different role","failed":"Failed"}'

if [[ "$MODE" == dry-run ]]; then
  summary "## Snyk access: dry run"
else
  summary "## Snyk access: sync complete"
fi
summary ""
summary "- **Snyk Organization:** ${ORG_NAME:-unknown} (\`$ORG_ID\`), resolved from $ORG_SOURCE"
summary "- **Access file:** \`$ACCESS_FILE\`"
if [[ "$MODE" == dry-run ]]; then
  summary "- **Would add:** $WOULD_ADD"
else
  summary "- **Added:** $ADDED"
fi
summary "- **Skipped:** $(($(count_outcome already_member) + $(count_outcome different_role)))"
summary "- **Failed:** $FAILED"
summary "- **Not found in the Snyk Group:** $UNRESOLVED_COUNT"

if [[ $(jq 'length' <<<"$RESULTS") -gt 0 ]]; then
  summary ""
  summary "| Email | Role | Result | Detail |"
  summary "| --- | --- | --- | --- |"
  jq -r --argjson roles "$ROLE_LABELS" --argjson labels "$OUTCOME_LABELS" '
    .[] | "| \(.email) | \($roles[.role]) | \($labels[.outcome]) | \(.detail) |"' <<<"$RESULTS" |
    while IFS= read -r line; do summary "$line"; done
fi

if ((UNRESOLVED_COUNT > 0)); then
  summary ""
  summary "### Emails not found in the Snyk Group"
  summary ""
  summary "Each person must log in to Snyk, or be invited to the Snyk Group, before the action can add them. The next run picks them up."
  summary ""
  jq -r '.[] | "- \(.email)"' <<<"$UNRESOLVED" | while IFS= read -r line; do summary "$line"; done
  jq -r '.[] | .email' <<<"$UNRESOLVED" | while IFS= read -r email; do
    printf '::warning::%s was not found in the Snyk Group and was skipped.\n' "$email" >&2
  done
fi

jq -r '.[] | select(.outcome == "failed") | "\(.email): \(.detail)"' <<<"$RESULTS" |
  while IFS= read -r line; do error "Could not add $line"; done

((FAILED == 0)) || exit 1
if [[ "$FAIL_ON_UNRESOLVED" == true ]] && ((UNRESOLVED_COUNT > 0)); then
  exit 1
fi
