package com.harness.llm.ui;

import java.awt.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Defines severity levels for findings with associated colors and display properties.
 */
public enum FindingSeverity {
    CRITICAL("Critical", new Color(220, 53, 69), new Color(255, 255, 255), "🔴"),
    HIGH("High", new Color(233, 128, 34), new Color(255, 255, 255), "🟠"),
    MEDIUM("Medium", new Color(255, 193, 7), new Color(0, 0, 0), "🟡"),
    LOW("Low", new Color(40, 167, 220), new Color(255, 255, 255), "🔵"),
    INFO("Info", new Color(150, 163, 166), new Color(255, 255, 255), "ℹ️"),
    UNKNOWN("Unknown", new Color(128, 128, 128), new Color(255, 255, 255), "⚪");
    
    private final String displayName;
    private final Color backgroundColor;
    private final Color textColor;
    private final String emoji;
    
    private static final Map<String, FindingSeverity> BY_NAME = new HashMap<>();
    
    static {
        for (FindingSeverity severity : values()) {
            BY_NAME.put(severity.displayName.toLowerCase(), severity);
            BY_NAME.put(severity.name().toLowerCase(), severity);
        }
    }
    
    FindingSeverity(String displayName, Color backgroundColor, Color textColor, String emoji) {
        this.displayName = displayName;
        this.backgroundColor = backgroundColor;
        this.textColor = textColor;
        this.emoji = emoji;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public Color getBackgroundColor() {
        return backgroundColor;
    }
    
    public Color getTextColor() {
        return textColor;
    }
    
    public String getEmoji() {
        return emoji;
    }
    
    /**
     * Get severity by name (case-insensitive).
     */
    public static FindingSeverity fromString(String name) {
        if (name == null || name.isEmpty()) {
            return UNKNOWN;
        }
        return BY_NAME.getOrDefault(name.toLowerCase(), UNKNOWN);
    }
    
    /**
     * Get the numeric weight for sorting (higher = more severe).
     */
    public int getWeight() {
        return switch (this) {
            case CRITICAL -> 5;
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFO -> 1;
            default -> 0;
        };
    }
    
    /**
     * Check if this severity is at least as severe as another.
     */
    public boolean isAtLeast(FindingSeverity other) {
        return this.getWeight() >= other.getWeight();
    }
}
