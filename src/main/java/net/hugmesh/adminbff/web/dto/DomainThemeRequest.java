package net.hugmesh.adminbff.web.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * The theme SELECTION a superadmin or domain admin submits for one domain.
 *
 * <p>Validated at the boundary rather than left to the database, because the failure mode
 * otherwise is silent: an out-of-vocabulary ramp does not raise anything, it renders the
 * fallback, and "my choice was ignored" is the exact complaint this feature line has
 * already produced twice. A clean 400 naming the field is the honest answer.
 *
 * <p>The hex patterns intentionally mirror the {@code domain_theme_*_hex_chk} CHECK
 * constraints in changeset 340-2. The DB constraint stays as the backstop for anything
 * that reaches the table by another path; this is what makes a bad colour a 400 instead
 * of a 500 for the operator typing it into the admin UI.
 */
public record DomainThemeRequest(

        /*
         * A theme_presets.PRESETS id. Deliberately shape-validated, NOT enumerated: the
         * preset table is data and grows (12 desktop schemes landed in a single commit),
         * so an enum here would reject a brand-new preset until Java caught up.
         */
        @NotBlank(message = "preset is required")
        @Size(max = 64, message = "preset is too long")
        @Pattern(regexp = "^[a-z0-9][a-z0-9-]*$",
                message = "preset must be a lowercase id")
        String preset,

        /*
         * theme_presets.MODES — the time-of-day ramp. This one IS a closed set, so it is
         * enumerated: the vocabulary lives in hugmesh-generator/studio/hugmesh_studio/
         * core/theme_presets.py (RAMPS), and adding a ramp there means adding it here.
         * That cross-language duplication is deliberate and is the price of rejecting a
         * typo at the boundary; the alternative is a theme that silently renders wrong.
         */
        @Pattern(regexp = "^(dark|light|dawn|morning|afternoon|dusk|evening|midnight)?$",
                message = "ramp must be one of dark, light, dawn, morning, afternoon, dusk, evening, midnight")
        String ramp,

        /* theme.STYLE_VARIANTS — the shape axis. Closed set, same reasoning as ramp. */
        @Pattern(regexp = "^(soft|sharp|outlined|elevated|flat|glass)?$",
                message = "style must be one of soft, sharp, outlined, elevated, flat, glass")
        String style,

        /*
         * theme.DECOR_VARIANTS — decorative nav-link text. Closed set, and the same
         * deliberate cross-language duplication as ramp and style: the vocabulary lives in
         * hugmesh-generator/studio/hugmesh_studio/core/theme.py (DECOR_VARIANTS), adding
         * one there means adding it here, and the price buys a named 400 instead of a
         * silently plain-chrome render.
         *
         * OMITTED MEANS 'none', not "leave whatever is stored". An admin UI with no decor
         * control therefore turns decoration OFF when it saves, which is the point: the
         * Studio could switch it on and nothing could switch it back.
         */
        @Pattern(regexp = "^(none|uwu|arrows|terminal|sparkle)?$",
                message = "decor must be one of none, uwu, arrows, terminal, sparkle")
        String decor,

        /* Optional hand-picked overrides; null/blank means "use the preset's colours". */
        @Pattern(regexp = "^(#[0-9A-Fa-f]{6})?$",
                message = "primaryHex must be a #rrggbb colour")
        String primaryHex,

        @Pattern(regexp = "^(#[0-9A-Fa-f]{6})?$",
                message = "secondaryHex must be a #rrggbb colour")
        String secondaryHex,

        /*
         * OPTIONAL, and only the Studio sends it: the already-derived stylesheet for this
         * selection. The colour maths has one implementation (Python) and this is how its
         * output reaches the mesh without a second one appearing in Java.
         *
         * The admin UI omits it -- it cannot derive -- and the service then keeps the
         * previous render if the selection is unchanged and drops it if not, because a
         * stale sheet for a new selection renders the wrong brand while reporting the new
         * one saved. Size-capped: a token sheet is ~7 KB, so a megabyte of "CSS" is an
         * abuse of an authenticated endpoint rather than a theme.
         */
        @Size(max = 262144, message = "renderedCss is too large")
        String renderedCss) {
}
