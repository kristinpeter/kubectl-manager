#!/bin/bash
# kubectl-manager bash completion script

_kubectl_manager_completions() {
    local cur prev words cword
    _init_completion || return

    local kubectl_manager_commands="versions configs clusters use run status help"
    local versions_subcommands="list installed install"
    local configs_subcommands="list add"
    local clusters_subcommands="list"

    # Complete main commands
    if [[ $cword -eq 1 ]]; then
        mapfile -t COMPREPLY < <(compgen -W "$kubectl_manager_commands" -- "$cur")
        return
    fi

    # Complete subcommands based on main command
    case "${words[1]}" in
        versions)
            if [[ $cword -eq 2 ]]; then
                mapfile -t COMPREPLY < <(compgen -W "$versions_subcommands" -- "$cur")
            elif [[ $cword -eq 3 && "${words[2]}" == "install" ]]; then
                # For install command, suggest some common versions
                local common_versions="1.33.0 1.32.0 1.31.0 1.30.0 1.29.0 1.28.0"
                mapfile -t COMPREPLY < <(compgen -W "$common_versions" -- "$cur")
            fi
            ;;
        configs)
            if [[ $cword -eq 2 ]]; then
                mapfile -t COMPREPLY < <(compgen -W "$configs_subcommands" -- "$cur")
            elif [[ $cword -eq 4 && "${words[2]}" == "add" ]]; then
                # For kubeconfig file argument, complete file paths
                mapfile -t COMPREPLY < <(compgen -f -- "$cur")
            fi
            ;;
        clusters)
            if [[ $cword -eq 2 ]]; then
                mapfile -t COMPREPLY < <(compgen -W "$clusters_subcommands" -- "$cur")
            fi
            ;;
        use)
            if [[ $cword -eq 2 ]]; then
                # Complete with available cluster names
                local clusters
                if [[ -f ".kubectl-manager/config.json" ]]; then
                    clusters=$(python3 -c "
import json, sys
try:
    with open('.kubectl-manager/config.json', 'r') as f:
        config = json.load(f)
    print(' '.join(config.get('clusters', {}).keys()))
except:
    pass
" 2>/dev/null)
                fi
                mapfile -t COMPREPLY < <(compgen -W "$clusters" -- "$cur")
            elif [[ $cword -eq 3 && "$prev" == "--kubectl" ]]; then
                # Complete with installed kubectl versions
                local installed_versions
                if [[ -d "bin" ]]; then
                    installed_versions=$(find bin -name 'kubectl-*' 2>/dev/null | sed 's/.*kubectl-//' | tr '\n' ' ')
                fi
                mapfile -t COMPREPLY < <(compgen -W "$installed_versions" -- "$cur")
            elif [[ $cword -eq 3 || ($cword -eq 4 && "${words[2]}" == "--kubectl") ]]; then
                mapfile -t COMPREPLY < <(compgen -W "--kubectl" -- "$cur")
            fi
            ;;
        run)
            # For run command, complete with kubectl commands
            if [[ $cword -ge 2 ]]; then
                local kubectl_commands="get describe create apply delete patch edit logs exec port-forward proxy cp auth drain cordon uncordon taint top rollout scale autoscale certificate cluster-info config version api-resources api-versions explain diff kustomize"
                if [[ $cword -eq 2 ]]; then
                    mapfile -t COMPREPLY < <(compgen -W "$kubectl_commands" -- "$cur")
                else
                    # For kubectl subcommands, provide basic resource types
                    case "${words[2]}" in
                        get|describe|delete|edit|patch)
                            local resources="pods po services svc deployments deploy replicasets rs daemonsets ds statefulsets sts jobs cronjobs cj nodes no namespaces ns configmaps cm secrets persistentvolumes pv persistentvolumeclaims pvc ingresses ing"
                            mapfile -t COMPREPLY < <(compgen -W "$resources" -- "$cur")
                            ;;
                        logs|exec)
                            # Complete with pod names if possible - simplified for now
                            mapfile -t COMPREPLY < <(compgen -f -- "$cur")
                            ;;
                        *)
                            # Default to file completion for other cases
                            mapfile -t COMPREPLY < <(compgen -f -- "$cur")
                            ;;
                    esac
                fi
            fi
            ;;
    esac
}

# Register the completion function
complete -F _kubectl_manager_completions kubectl-manager.py
complete -F _kubectl_manager_completions ./kubectl-manager.py

# Also provide completion for common aliases
complete -F _kubectl_manager_completions km
complete -F _kubectl_manager_completions kubectl-manager