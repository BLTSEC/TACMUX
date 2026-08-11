_tacmux_complete() {
    local current="${COMP_WORDS[COMP_CWORD]}" command_name="${COMP_WORDS[1]:-}"
    local commands="engagement start stop pause resume list status archive rename mkop pick logs log clip health config help version"
    local config="${TACMUX_CONFIG:-$HOME/.config/tacmux/tacmux.conf}"
    local state_file="${TACMUX_ENGAGEMENT_STATE:-$HOME/.config/tacmux/engagementrc}"
    [[ -f "$config" ]] && source "$config"
    [[ -z "${TACMUX_ENGAGEMENT:-}" && -f "$state_file" ]] && source "$state_file"
    : "${TACMUX_WORKSPACE:=$HOME/workspace}"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands" -- "$current"))
        return
    fi

    case "$command_name" in
        engagement)
            local names="clear" marker
            for marker in "$TACMUX_WORKSPACE"/*/ENGAGEMENT.md; do
                [[ -f "$marker" ]] && names+=" $(basename "$(dirname "$marker")")"
            done
            COMPREPLY=($(compgen -W "$names" -- "$current"))
            ;;
        start|stop|pause|resume|status|archive|rename)
            local base="$TACMUX_WORKSPACE" names="" directory
            [[ -n "${TACMUX_ENGAGEMENT:-}" ]] && base="$base/$TACMUX_ENGAGEMENT/targets"
            for directory in "$base"/*/; do
                [[ -d "$directory" ]] && names+=" $(basename "$directory")"
            done
            COMPREPLY=($(compgen -W "$names" -- "$current"))
            ;;
        log) COMPREPLY=($(compgen -W "start force stop toggle capture status" -- "$current")) ;;
        logs|mkop) COMPREPLY=($(compgen -d -- "$current")) ;;
    esac
}

complete -F _tacmux_complete tacmux
