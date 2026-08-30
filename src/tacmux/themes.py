"""Curated Textual themes for the operator cockpit."""

from __future__ import annotations

from textual.theme import Theme


DEFAULT_THEME = "bltsec"
CURATED_THEME_NAMES = frozenset(
    {
        DEFAULT_THEME,
        "catppuccin-mocha",
        "dracula",
        "gruvbox",
        "nord",
        "rose-pine-moon",
        "solarized-dark",
        "textual-dark",
        "tokyo-night",
    }
)

BLTSEC_THEME = Theme(
    name=DEFAULT_THEME,
    primary="#46BFD0",
    secondary="#3694A1",
    warning="#D7B66F",
    error="#E06C75",
    success="#63C7A5",
    accent="#78E3EC",
    foreground="#D5E1E2",
    background="#0E1517",
    surface="#131E20",
    panel="#233537",
    dark=True,
    variables={
        "block-cursor-background": "#78E3EC",
        "block-cursor-foreground": "#0E1517",
        "block-cursor-text-style": "none",
        "border": "#3694A1",
        "border-blurred": "#2E4C4E",
        "button-color-foreground": "#0E1517",
        "footer-background": "#182729",
        "footer-key-foreground": "#78E3EC",
        "input-selection-background": "#3694A1 35%",
    },
)
