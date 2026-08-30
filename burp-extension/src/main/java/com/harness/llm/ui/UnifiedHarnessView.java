package com.harness.llm.ui;

import javax.swing.*;
import java.awt.*;

/**
 * Combines the Attack Surface Map (score/rank everything Burp has seen)
 * and the Results view (per-exchange findings + live progress) into one
 * suite tab, instead of the analyst having to switch between two
 * separate tabs to go from "what should I test" to "what did the
 * harness find."
 *
 * Deliberately pure composition: both {@link AttackSurfacePanel} and
 * {@link HarnessPanel} are constructed exactly as before by
 * LlmHarnessExtension and handed in here fully formed. This class does
 * not reach into either panel's internals or change their behavior --
 * it only lays them out together, so the risk surface of "unifying"
 * the view is the JSplitPane wiring, not the two panels themselves.
 */
public class UnifiedHarnessView extends JPanel {

    public UnifiedHarnessView(AttackSurfacePanel attackSurfacePanel, HarnessPanel harnessPanel) {
        setLayout(new BorderLayout());

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, attackSurfacePanel, harnessPanel);
        split.setResizeWeight(0.45); // attack surface map gets slightly less than half by default
        split.setOneTouchExpandable(true);
        split.setDividerLocation(320);

        add(split, BorderLayout.CENTER);
    }
}
