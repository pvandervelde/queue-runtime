# PowerShell script to update GitHub label colors for pvandervelde/RepoRoller
# Requires: GitHub CLI (gh) installed and authenticated
# Colors chosen from ColorBrewer/Colorblind-safe palettes for accessibility

# Label definitions: name, color, description
$labelDefinitions = @(
    @{ Name = "comp:tooling"; Color = "91c764"; Description = "Tooling component" }

    @{ Name = "type:feat"; Color = "fcc37b"; Description = "New feature or enhancement" }
    @{ Name = "type:fix"; Color = "fcc37b"; Description = "Bug fix" }
    @{ Name = "type:chore"; Color = "fcc37b"; Description = "Chore or maintenance task" }
    @{ Name = "type:docs"; Color = "fcc37b"; Description = "Documentation changes" }
    @{ Name = "type:refactor"; Color = "fcc37b"; Description = "Code refactoring" }
    @{ Name = "type:style"; Color = "fcc37b"; Description = "Code style changes" }
    @{ Name = "type:perf"; Color = "fcc37b"; Description = "Performance improvements" }
    @{ Name = "type:test"; Color = "fcc37b"; Description = "Test-related changes" }
    @{ Name = "type:ci"; Color = "fcc37b"; Description = "Continuous integration or build changes" }
    @{ Name = "type:revert"; Color = "fcc37b"; Description = "Revert changes" }

    @{ Name = "status:needs-triage"; Color = "64befb"; Description = "Needs triage or review" }
    @{ Name = "status:draft"; Color = "64befb"; Description = "Work is in draft mode" }
    @{ Name = "status:in-progress"; Color = "64befb"; Description = "Work in progress" }
    @{ Name = "status:needs-review"; Color = "64befb"; Description = "Needs code or design review" }
    @{ Name = "status:blocked"; Color = "64befb"; Description = "Blocked by another issue or dependency" }
    @{ Name = "status:completed"; Color = "64befb"; Description = "Work completed" }

    @{ Name = "prio:high"; Color = "e94648"; Description = "High priority" }
    @{ Name = "prio:medium"; Color = "e94648"; Description = "Medium priority" }
    @{ Name = "prio:low"; Color = "e94648"; Description = "Low priority" }

    @{ Name = "size:xs"; Color = "fecc3e"; Description = "Extra small change" }
    @{ Name = "size:s"; Color = "fecc3e"; Description = "Small change" }
    @{ Name = "size:m"; Color = "fecc3e"; Description = "Medium change" }
    @{ Name = "size:l"; Color = "fecc3e"; Description = "Large change" }
    @{ Name = "size:xl"; Color = "fecc3e"; Description = "Extra large change" }

    @{ Name = "feedback:discussion"; Color = "c8367a"; Description = "Discussion or open feedback" }
    @{ Name = "feedback:rfc"; Color = "c8367a"; Description = "Request for comments (RFC)" }
    @{ Name = "feedback:question"; Color = "c8367a"; Description = "General question or inquiry" }

    @{ Name = "inactive:duplicate"; Color = "d3d8de"; Description = "Duplicate issue or PR" }
    @{ Name = "inactive:wontfix"; Color = "d3d8de"; Description = "Will not fix" }
    @{ Name = "inactive:by-design"; Color = "d3d8de"; Description = "Closed as by design" }

    @{ Name = "pr-issue:invalid-title-format"; Color = "986ee2"; Description = "The PR title does not follow the required format" }
    @{ Name = "pr-issue:missing-work-item"; Color = "986ee2"; Description = "The PR is missing a linked work item" }
    @{ Name = "pr-issue:pending-stability"; Color = "986ee2"; Description = "The PR is pending stability review" }

    @{ Name = "rr:override-major"; Color = "57ab5a"; Description = "Override required for major version change" }
    @{ Name = "rr:override-minor"; Color = "57ab5a"; Description = "Override required for minor version change" }
    @{ Name = "rr:override-patch"; Color = "57ab5a"; Description = "Override required for patch version change" }
)

# Get all current labels from GitHub, handling pagination
function Get-AllLabels
{
    $perPage = 100
    $labels = gh label list --json name --limit $perPage | ConvertFrom-Json
    if ($labels.Count -eq 0)
    {
        break
    }

    $allLabels = @()
    $allLabels += $labels

    return $allLabels | ForEach-Object { $_.name }
}
$currentLabels = Get-AllLabels

# Create or update labels as needed
foreach ($labelDef in $labelDefinitions)
{
    $name = $labelDef.Name
    $color = $labelDef.Color
    $desc = $labelDef.Description

    if ($currentLabels -contains $name)
    {
        Write-Host "Updating label '$name' to color #$color and description '$desc'"
        gh label edit "$name" --color $color --description "$desc"
    }
    else
    {
        Write-Host "Creating label '$name' with color #$color and description '$desc'"
        gh label create "$name" --color $color --description "$desc"
    }
}

# Remove labels not in the desired list
$desiredNames = $labelDefinitions | ForEach-Object { $_.Name }
$labelsToRemove = $currentLabels | Where-Object { $desiredNames -notcontains $_ }
foreach ($label in $labelsToRemove)
{
    Write-Host "Deleting label '$label' (not in desired list)"
    gh label delete "$label" --yes
}
