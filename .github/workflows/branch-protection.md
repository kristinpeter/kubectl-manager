# Branching Strategy and Workflow

## Branch Structure

### Master Branch (Production)
- **Purpose**: Production-ready code only
- **Protection**: Requires PR reviews, status checks must pass
- **Merges**: Only from develop branch via PR
- **Direct commits**: Prohibited except for hotfixes

### Develop Branch (Integration)
- **Purpose**: Integration branch for development work
- **Protection**: Requires PR reviews for merges
- **Source**: Feature branches merge here
- **Testing**: All tests must pass before merge to master

### Feature Branches
- **Naming**: `feature/description` or `feature/issue-number`
- **Source**: Branch from develop
- **Merge target**: Back to develop via PR
- **Lifecycle**: Delete after successful merge

## Workflow Guidelines

### Development Process
1. Create feature branch from develop: `git checkout -b feature/new-feature develop`
2. Develop and test changes locally
3. Run full test suite: `./run_optimized_tests.sh all`
4. Push feature branch and create PR to develop
5. After review and CI success, merge to develop
6. Delete feature branch

### Release Process
1. Create release branch from develop: `git checkout -b release/v1.1.0 develop`
2. Final testing and bug fixes on release branch
3. Merge release branch to master via PR
4. Tag release on master: `git tag v1.1.0`
5. Merge release branch back to develop
6. Delete release branch

### Hotfix Process
1. Create hotfix branch from master: `git checkout -b hotfix/critical-fix master`
2. Apply minimal fix and test
3. Merge to master via PR
4. Merge back to develop
5. Tag new patch version

## Required Checks
- All tests must pass (`./run_optimized_tests.sh all`)
- Security scan with bandit must pass
- Code quality checks (shellcheck, pylint)
- Manual review required for all PRs

## Branch Protection Rules (GitHub)
```bash
# Enable branch protection for master
gh api repos/kristinpeter/kubectl-manager/branches/master/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["tests"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field restrictions=null
```