#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: generate-release-notes.sh <tag> <version> <image> <digest> <output>}"
version="${2:?usage: generate-release-notes.sh <tag> <version> <image> <digest> <output>}"
image="${3:?usage: generate-release-notes.sh <tag> <version> <image> <digest> <output>}"
digest="${4:?usage: generate-release-notes.sh <tag> <version> <image> <digest> <output>}"
output="${5:?usage: generate-release-notes.sh <tag> <version> <image> <digest> <output>}"

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
server_url="${GITHUB_SERVER_URL:-https://github.com}"

if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "release tag must match v<major>.<minor>.<patch>[-suffix], got: ${tag}" >&2
  exit 1
fi

commit="$(git rev-list -n1 "${tag}")"
commit_short="$(git rev-parse --short=7 "${commit}")"
commit_subject="$(git show -s --format=%s "${commit}")"
commit_date="$(git show -s --format=%cI "${commit}")"

major="${version%%.*}"
rest="${version#*.}"
minor="${rest%%.*}"

publish_latest=true
publish_major=true

if [[ "${version}" == *-* ]]; then
  publish_latest=false
  publish_major=false
elif [[ "${major}" == "0" ]]; then
  publish_major=false
fi

previous_tag=""
last_tag=""
while IFS= read -r candidate; do
  [[ -z "${candidate}" ]] && continue

  if [[ "${candidate}" == "${tag}" ]]; then
    previous_tag="${last_tag}"
    break
  fi

  last_tag="${candidate}"
done < <(git tag --list 'v*' --sort=version:refname)

range="${tag}"
compare_url=""
if [[ -n "${previous_tag}" ]]; then
  range="${previous_tag}..${tag}"
  compare_url="${server_url}/${repo}/compare/${previous_tag}...${tag}"
fi

published_tags=(
  "${image}:${version}"
  "${image}:${tag}"
)

if [[ "${version}" != *-* ]]; then
  published_tags+=("${image}:${major}.${minor}")
fi

if [[ "${publish_major}" == "true" ]]; then
  published_tags+=("${image}:${major}")
fi

if [[ "${publish_latest}" == "true" ]]; then
  published_tags+=("${image}:latest")
fi

published_tags+=("${image}:sha-${commit_short}")

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

commits_file="${tmp_dir}/commits.md"
diff_file="${tmp_dir}/diff.txt"

git log --reverse --format='%H%x09%s' "${range}" | while IFS=$'\t' read -r sha subject; do
  [[ -z "${sha}" ]] && continue
  short_sha="$(git rev-parse --short=7 "${sha}")"
  printf -- '- [%s](%s/%s/commit/%s) %s\n' "${short_sha}" "${server_url}" "${repo}" "${sha}" "${subject}"
done > "${commits_file}"

if [[ ! -s "${commits_file}" ]]; then
  printf -- '- No commits found in `%s`\n' "${range}" > "${commits_file}"
fi

if [[ -n "${previous_tag}" ]]; then
  git diff --stat --summary "${range}" > "${diff_file}"
else
  empty_tree="$(git hash-object -t tree /dev/null)"
  git diff --stat --summary "${empty_tree}" "${tag}^{tree}" > "${diff_file}"
fi

if [[ ! -s "${diff_file}" ]]; then
  printf 'No file-level diff summary is available for `%s`.\n' "${range}" > "${diff_file}"
fi

{
  echo "# gh-proxy ${version}"
  echo
  echo "## Release Metadata"
  echo
  echo "- Tag: \`${tag}\`"
  echo "- Commit: [\`${commit_short}\`](${server_url}/${repo}/commit/${commit}) ${commit_subject}"
  echo "- Commit Date: \`${commit_date}\`"
  echo "- Primary Image: \`${image}:${version}\`"
  echo "- Digest: \`${digest}\`"
  if [[ -n "${previous_tag}" ]]; then
    echo "- Previous Tag: \`${previous_tag}\`"
    echo "- Compare: [\`${previous_tag}...${tag}\`](${compare_url})"
  else
    echo "- Previous Tag: none"
    echo "- Compare: initial release history for \`${tag}\`"
  fi
  echo
  echo "## Published Container Tags"
  echo
  for published_tag in "${published_tags[@]}"; do
    echo "- \`${published_tag}\`"
  done
  echo
  echo "## Full Commit Log"
  echo
  cat "${commits_file}"
  echo
  echo "## Diff Summary"
  echo
  echo '```text'
  cat "${diff_file}"
  echo '```'
} > "${output}"
