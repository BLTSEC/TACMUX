#compdef tacmux

_tacmux_completion_context() {
    local config="${TACMUX_CONFIG:-$HOME/.config/tacmux/tacmux.conf}"
    local state="${TACMUX_ENGAGEMENT_STATE:-$HOME/.config/tacmux/engagementrc}"
    [[ -f "$config" ]] && source "$config"
    [[ -z "${TACMUX_ENGAGEMENT:-}" && -f "$state" ]] && source "$state"
    : "${TACMUX_WORKSPACE:=$HOME/workspace}"
}

_tacmux_targets() {
    _tacmux_completion_context
    local base="$TACMUX_WORKSPACE" targets=() directory
    [[ -n "${TACMUX_ENGAGEMENT:-}" ]] && base="$base/$TACMUX_ENGAGEMENT/targets"
    for directory in "$base"/*(N/); do targets+=("${directory:t}"); done
    typeset -U targets
    compadd -a targets
}

_tacmux_engagements() {
    _tacmux_completion_context
    local names=() marker
    for marker in "$TACMUX_WORKSPACE"/*/ENGAGEMENT.md(N); do names+=("${marker:h:t}"); done
    names+=(clear)
    compadd -a names
}

_tacmux() {
    local -a commands
    commands=(
        'engagement:show or select engagement mode'
        'start:start a target session'
        'stop:stop a target session'
        'pause:detach a target session'
        'resume:attach a target session'
        'list:list active target sessions'
        'status:show target status'
        'archive:archive a target workspace'
        'rename:rename a target workspace'
        'mkop:create a target directory tree'
        'pick:select an active session with fzf'
        'logs:browse log files'
        'log:control pane logging'
        'clip:copy stdin to the trusted clipboard path'
        'health:check dependencies and integration'
        'config:show effective configuration'
        'help:show detailed help'
        'version:print version'
    )

    _arguments -C '1:command:->command' '*::argument:->args'
    case "$state" in
        command) _describe command commands ;;
        args)
            case "$words[2]" in
                engagement) _tacmux_engagements ;;
                start|stop|pause|resume|status|archive|rename) _tacmux_targets ;;
                logs|mkop) _files -/ ;;
                log) compadd start force stop toggle capture status ;;
            esac
            ;;
    esac
}

compdef _tacmux tacmux
