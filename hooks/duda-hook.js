/**
 * DUDA Hook — Claude Code UserPromptSubmit trigger detection
 *
 * Detects DUDA-relevant keywords in user prompts and injects
 * DUDA context to activate the appropriate mode.
 *
 * Installation:
 *   Add to .claude/settings.json → hooks → UserPromptSubmit
 *
 * Hook types supported:
 *   - "command" (default): runs as shell command
 *   - "http" (CC v2.1.63+): runs as HTTP endpoint
 */

const TRIGGERS = {
  // INIT mode triggers
  init: {
    explicit: [
      "duda init",
      "duda initialize",
      "duda update",
      "initialize isolation map",
      "initialize duda",
      "create isolation map",
      "generate duda map",
      "scan project structure",
    ],
    patterns: [
      /\bduda\s+(init|initialize|update|setup)\b/i,
      /\binitialize\s+(isolation|duda)\s*map\b/i,
      /\bgenerate\s+duda[_\s]?map\b/i,
    ],
  },

  // SCAN mode triggers (lite)
  scan: {
    explicit: [
      "duda scan",
    ],
    patterns: [
      /\bduda\s+scan\s+/i,
      /\bis\s+(this|it)\s+safe\s+to\s+import\b/i,
      /\bquick\s+(check|scan|analyze)\b.*\b(import|file|component)\b/i,
    ],
  },

  // SCOPE mode triggers (feature-centric analysis)
  scope: {
    explicit: [
      "duda scope",
    ],
    patterns: [
      /\bduda\s+scope\s+/i,
      /\bshow\b.*\bfiles?\b.*\brelated\s+to\b/i,
      /\bcheck\b.*\bisolation\b.*\b(for|of)\b.*\b(feature|system|module)\b/i,
      /\banalyze\b.*\bfeature\b.*\bisolation\b/i,
      /\bwhat\s+files?\b.*\binvolved\s+in\b/i,
      /\bfind\b.*\ball\b.*\bfiles?\b.*\b(for|about|related)\b/i,
    ],
  },

  // TRANSPLANT mode triggers
  transplant: {
    explicit: [
      "duda transplant",
      "duda migrate",
    ],
    patterns: [
      // Direct migration verbs
      /\b(migrate|port|transplant|copy\s+from|bring\s+over|move)\b.*\b(to|into|from)\b/i,
      // "use X in Y" patterns
      /\b(use|apply|reuse|share)\b.*\b(in|to|for|across)\b.*\b(app|layer|service|tenant|module)\b/i,
      // "I want to use X in Y"
      /\bi\s+(want|need|would\s+like)\s+to\s+use\b.*\bin\b/i,
      // "can I use X in Y?"
      /\bcan\s+i\s+use\b.*\bin\b/i,
      // "bring X to Y"
      /\bbring\b.*\bto\b.*\b(tenant|app|service|module|layer)\b/i,
      // "apply X to Y"
      /\bapply\b.*\bto\b.*\b(tenant|app|service|module|layer)\b/i,
      // Korean triggers (optional — for bilingual projects)
      /\b(가져와|복사|이식|적용|이동|붙여)\b/,
    ],
  },

  // ACT mode triggers (fix generation)
  act: {
    explicit: [
      "duda fix",
      "duda act",
      "duda apply fix",
    ],
    patterns: [
      /\bduda\s+(fix|act|apply|patch)\b/i,
      /\b(fix|patch|resolve)\s+(the\s+)?(contamination|breach|violation|isolation)\b/i,
      /\b(auto[- ]?fix|generate\s+fix|apply\s+fix)\b/i,
    ],
  },

  // GUARD mode triggers (CI/pre-commit gate)
  guard: {
    explicit: [
      "duda guard",
      "duda gate",
      "duda pre-commit",
    ],
    patterns: [
      /\bduda\s+(guard|gate|check[- ]?commit)\b/i,
      /\b(isolation\s+(check|gate)|pre[- ]?commit\s+check)\b.*\b(duda|isolation)\b/i,
      /\bcheck\s+staged\s+(files?\s+)?(for\s+)?(isolation|breach|contamination)\b/i,
    ],
  },

  // AUDIT mode triggers
  audit: {
    explicit: [
      "duda audit",
      "duda check",
      "duda diagnose",
    ],
    patterns: [
      // Data leak indicators
      /\b(data\s+leak|leaking\s+data|wrong\s+tenant|other\s+tenant)\b/i,
      /\b(showing\s+other|visible\s+to\s+other|cross[- ]tenant)\b/i,
      /\b(other\s+(company|org|organization)\s+data)\b/i,
      // Contamination indicators
      /\b(contamination|contaminated|polluted|broken\s+isolation)\b/i,
      /\b(isolation\s+(breach|violation|broken|failed))\b/i,
      // "Why is X visible/showing" patterns
      /\bwhy\s+is\b.*\b(visible|showing|appearing|displayed)\b/i,
      /\bshouldn.t\s+be\s+(visible|showing|there|accessible)\b/i,
      // Boundary violation indicators
      /\b(direct\s+db\s+access|direct\s+database|boundary\s+violation)\b/i,
      /\b(cross[- ]service|cross[- ]app)\s+(import|access|call)\b/i,
      // Unexpected behavior
      /\bsudden(ly)?\s+(showing|appeared|visible)\b/i,
      /\b(admin|platform|system)\s+(menu|panel|data)\b.*\b(tenant|store|client)\b/i,
    ],
  },
};

/**
 * Detect which DUDA mode should be activated based on user prompt.
 * @param {string} prompt - The user's input message
 * @returns {{ mode: string|null, confidence: number, matches: string[] }}
 */
function detectMode(prompt) {
  const lower = prompt.toLowerCase().trim();
  let bestMode = null;
  let bestConfidence = 0;
  let bestMatches = [];

  for (const [mode, { explicit, patterns }] of Object.entries(TRIGGERS)) {
    let confidence = 0;
    const matches = [];

    // Explicit trigger check (highest confidence)
    for (const trigger of explicit) {
      if (lower.includes(trigger.toLowerCase())) {
        confidence = 1.0;
        matches.push(`explicit: "${trigger}"`);
      }
    }

    // Pattern matching (variable confidence)
    if (confidence < 1.0) {
      for (const pattern of patterns) {
        const match = prompt.match(pattern);
        if (match) {
          confidence = Math.max(confidence, 0.8);
          matches.push(`pattern: ${match[0]}`);
        }
      }
    }

    // Context boosters
    if (confidence > 0 && confidence < 1.0) {
      // Boost if file paths or layer names are mentioned
      if (/\b(src\/|apps\/|packages\/|\.tsx?|\.jsx?)\b/.test(prompt)) {
        confidence = Math.min(confidence + 0.1, 1.0);
        matches.push("context: file path detected");
      }
      // Boost if specific component/module names are mentioned
      if (/\b[A-Z][a-z]+[A-Z]/.test(prompt)) {
        confidence = Math.min(confidence + 0.05, 1.0);
        matches.push("context: component name detected");
      }
    }

    if (confidence > bestConfidence) {
      bestMode = mode;
      bestConfidence = confidence;
      bestMatches = matches;
    }
  }

  // Minimum confidence threshold
  if (bestConfidence < 0.7) {
    return { mode: null, confidence: 0, matches: [] };
  }

  return { mode: bestMode, confidence: bestConfidence, matches: bestMatches };
}

/**
 * Generate context injection message for detected mode.
 * @param {string} mode - Detected DUDA mode
 * @param {number} confidence - Detection confidence
 * @returns {string} Context message to inject
 */
function generateContext(mode, confidence) {
  const modeDescriptions = {
    init: "DUDA INIT mode — Generate isolation map via topological exploration",
    scan: "DUDA SCAN mode — Quick single-file/directory analysis (lite, no map required)",
    scope: "DUDA SCOPE mode — Feature-centric isolation analysis (discovers related files by keyword)",
    transplant: "DUDA TRANSPLANT mode — Analyze and safely migrate code across isolation boundaries",
    act: "DUDA ACT mode — Generate and apply isolation fixes (post-AUDIT or post-TRANSPLANT)",
    guard: "DUDA GUARD mode — Check staged files for isolation breaches (CI/pre-commit gate)",
    audit: "DUDA AUDIT mode — Trace and fix isolation contamination",
  };

  return [
    `[DUDA] ${modeDescriptions[mode] || mode}`,
    `Confidence: ${(confidence * 100).toFixed(0)}%`,
    `Follow the DUDA SKILL.md ${mode.toUpperCase()} mode flow.`,
  ].join("\n");
}

// ── Main: Hook entry point ──────────────────────────────────────────────────

function main() {
  // Read user prompt from stdin (Claude Code hook protocol)
  let input = "";
  const stdin = process.stdin;
  stdin.setEncoding("utf8");

  stdin.on("data", (chunk) => {
    input += chunk;
  });

  stdin.on("end", () => {
    try {
      const hookData = JSON.parse(input);
      const prompt = hookData.message?.content || hookData.prompt || "";

      if (!prompt) {
        console.log(JSON.stringify({ result: "pass" }));
        return;
      }

      const { mode, confidence, matches } = detectMode(prompt);

      if (mode) {
        const context = generateContext(mode, confidence);
        console.log(
          JSON.stringify({
            result: "pass",
            message: context,
          })
        );
      } else {
        console.log(JSON.stringify({ result: "pass" }));
      }
    } catch (e) {
      // On parse error, pass through silently
      console.log(JSON.stringify({ result: "pass" }));
    }
  });
}

main();

// Export for testing
if (typeof module !== "undefined") {
  module.exports = { detectMode, generateContext, TRIGGERS };
}
