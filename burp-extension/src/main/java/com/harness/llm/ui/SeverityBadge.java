package com.harness.llm.ui;

import javax.swing.*;
import java.awt.*;

/**
 * A visual badge component for displaying finding severity.
 */
public class SeverityBadge extends JLabel {
    
    private final FindingSeverity severity;
    
    public SeverityBadge(FindingSeverity severity) {
        this.severity = severity;
        setText(severity.getEmoji() + " " + severity.getDisplayName());
        setOpaque(true);
        setBackground(severity.getBackgroundColor());
        setForeground(severity.getTextColor());
        setFont(new Font(Font.SANS_SERIF, Font.BOLD, 11));
        setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        setHorizontalAlignment(SwingConstants.CENTER);
    }
    
    public SeverityBadge(String severityName) {
        this(FindingSeverity.fromString(severityName));
    }
    
    public FindingSeverity getSeverity() {
        return severity;
    }
    
    @Override
    public Dimension getPreferredSize() {
        Dimension dim = super.getPreferredSize();
        // Ensure minimum width for consistency
        dim.width = Math.max(dim.width, 80);
        dim.height = Math.max(dim.height, 20);
        return dim;
    }
    
    @Override
    protected void paintComponent(Graphics g) {
        // Paint rounded rectangle background
        Graphics2D g2d = (Graphics2D) g.create();
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        
        int arc = 10; // Rounded corner radius
        g2d.setColor(getBackground());
        g2d.fillRoundRect(0, 0, getWidth(), getHeight(), arc, arc);
        
        g2d.dispose();
        
        // Paint text
        super.paintComponent(g);
    }
    
    @Override
    protected void paintBorder(Graphics g) {
        // Don't paint default border - we have rounded background
    }
}
