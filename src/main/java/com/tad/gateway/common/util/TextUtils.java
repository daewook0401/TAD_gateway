package com.tad.gateway.common.util;

import java.util.Locale;

public final class TextUtils {

    private TextUtils() {
    }

    public static String normalizeNullable(String value) {
        if (value == null) {
            return null;
        }

        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    public static String normalizeNullableLowerCase(String value) {
        String normalized = normalizeNullable(value);
        return normalized == null ? null : normalized.toLowerCase(Locale.ROOT);
    }

    public static String compactLowerCase(String value) {
        if (value == null) {
            return null;
        }

        String compacted = value.replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
        return compacted.isEmpty() ? null : compacted;
    }
}
