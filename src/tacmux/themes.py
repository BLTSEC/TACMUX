"""The BLTSEC visual identity for the operator cockpit."""

from textual.theme import Theme


DEFAULT_THEME = "bltsec"

BLTSEC_THEME = Theme(
    name=DEFAULT_THEME,
    primary="#68E7F0",
    secondary="#2FB5C8",
    accent="#7FD5DF",
    foreground="#DCECEF",
    background="#061012",
    surface="#0A181B",
    panel="#102126",
    success="#63C7A5",
    warning="#D7B66F",
    error="#E06C75",
    dark=True,
    variables={
        "text-muted": "#89A4A8",
        "text-disabled": "#89A4A8 55%",
        "block-cursor-background": "#68E7F0",
        "block-cursor-foreground": "#061012",
        "block-cursor-text-style": "bold",
        "block-cursor-blurred-background": "#68E7F0 24%",
        "block-cursor-blurred-foreground": "#DCECEF",
        "block-cursor-blurred-text-style": "none",
        "block-hover-background": "#68E7F0 14%",
        "border": "#68E7F0",
        "border-blurred": "#2FB5C8 45%",
        "button-color-foreground": "#061012",
        "footer-background": "#0A181B",
        "footer-foreground": "#DCECEF",
        "footer-key-foreground": "#68E7F0",
        "footer-description-foreground": "#DCECEF 82%",
        "footer-description-background": "#0A181B",
        "input-cursor-background": "#68E7F0",
        "input-cursor-foreground": "#061012",
        "input-cursor-text-style": "none",
        "input-selection-background": "#68E7F0 35%",
        "input-selection-foreground": "#DCECEF",
        "scrollbar": "#2FB5C8 55%",
        "scrollbar-hover": "#68E7F0 75%",
        "scrollbar-active": "#68E7F0",
        "scrollbar-background": "#061012",
        "scrollbar-background-hover": "#0A181B",
        "scrollbar-background-active": "#0A181B",
        "scrollbar-corner-color": "#061012",
        "screen-selection-background": "#68E7F0 35%",
        "screen-selection-foreground": "#DCECEF",
    },
)
