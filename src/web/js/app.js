/**
 * PassShield — Interactive Password Policy & Strength Engine
 * Matches Gradious OOPS Assignment Rules
 */

// Configuration matching OOPS Assignment Policy
const POLICY_CONFIG = {
  minLength: 8,
  maxLength: 14,
  forbiddenWords: ["password", "12345", "qwerty", "admin", "username"],
  specialChars: "@#$%^&*!._-"
};

// DOM Elements
const passwordInput = document.getElementById("password-input");
const btnToggleVisibility = document.getElementById("btn-toggle-visibility");
const eyeIcon = document.getElementById("eye-icon");
const btnCopyPassword = document.getElementById("btn-copy-password");
const btnClearPassword = document.getElementById("btn-clear-password");
const toastContainer = document.getElementById("toast-container");

// Verdict Elements
const acceptanceCard = document.getElementById("acceptance-card");
const acceptanceBadge = document.getElementById("acceptance-badge");
const acceptanceDesc = document.getElementById("acceptance-desc");
const acceptanceIcon = document.getElementById("acceptance-icon");

// Strength Elements
const strengthCard = document.getElementById("strength-card");
const strengthTitle = document.getElementById("strength-title");
const strengthPill = document.getElementById("strength-pill");
const seg1 = document.getElementById("seg-1");
const seg2 = document.getElementById("seg-2");
const seg3 = document.getElementById("seg-3");
const seg4 = document.getElementById("seg-4");
const entropyValue = document.getElementById("entropy-value");
const crackTimeValue = document.getElementById("crack-time-value");
const charCountValue = document.getElementById("char-count-value");

// Policy Checklist Elements
const policyLengthCard = document.getElementById("policy-length");
const statusLength = document.getElementById("status-length");
const fillLength = document.getElementById("fill-length");
const labelLengthCur = document.getElementById("label-length-cur");

const policyUpperCard = document.getElementById("policy-upper");
const statusUpper = document.getElementById("status-upper");
const countUpper = document.getElementById("count-upper");

const policyLowerCard = document.getElementById("policy-lower");
const statusLower = document.getElementById("status-lower");
const countLower = document.getElementById("count-lower");

const policyDigitCard = document.getElementById("policy-digit");
const statusDigit = document.getElementById("status-digit");
const countDigit = document.getElementById("count-digit");

const policySpecCard = document.getElementById("policy-spec");
const statusSpec = document.getElementById("status-spec");
const countSpec = document.getElementById("count-spec");
const specMatchedChars = document.getElementById("spec-matched-chars");

const policyForbiddenCard = document.getElementById("policy-forbidden");
const statusForbidden = document.getElementById("status-forbidden");
const forbiddenAlert = document.getElementById("forbidden-alert");

// Matrix Tiers
const tierStrong = document.getElementById("tier-strong");
const tierHigh = document.getElementById("tier-high");
const tierModerate = document.getElementById("tier-moderate");
const tierWeak = document.getElementById("tier-weak");

// Terminal & Export Elements
const terminalOutput = document.getElementById("terminal-output");
const btnCopyTerminal = document.getElementById("btn-copy-terminal");
const btnCopyReport = document.getElementById("btn-copy-report");
const btnToggleGenerator = document.getElementById("btn-toggle-generator");
const generatorCard = document.getElementById("generator-card");

// Generator Elements
const genLengthSlider = document.getElementById("gen-length");
const genLengthVal = document.getElementById("gen-length-val");
const btnGeneratePassword = document.getElementById("btn-generate-password");

/**
 * Toast Notification Helper
 */
function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      ${type === "success" 
        ? '<polyline points="20 6 9 17 4 12"/>' 
        : '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>'}
    </svg>
    <span>${message}</span>
  `;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "toastFadeOut 0.3s forwards";
    setTimeout(() => toast.remove(), 300);
  }, 2800);
}

/**
 * Core Password Analyzer Function
 */
function analyzePassword(password) {
  const len = password.length;
  const isLengthValid = len >= POLICY_CONFIG.minLength && len <= POLICY_CONFIG.maxLength;

  let uppCount = 0;
  let lowCount = 0;
  let digCount = 0;
  let specCount = 0;
  const matchedSpecials = [];

  for (const ch of password) {
    if (ch >= 'A' && ch <= 'Z') {
      uppCount++;
    } else if (ch >= 'a' && ch <= 'z') {
      lowCount++;
    } else if (ch >= '0' && ch <= '9') {
      digCount++;
    } else if (POLICY_CONFIG.specialChars.includes(ch)) {
      specCount++;
      if (!matchedSpecials.includes(ch)) {
        matchedSpecials.push(ch);
      }
    }
  }

  // Scan for forbidden words
  const lowerPwd = password.toLowerCase();
  const matchedForbidden = POLICY_CONFIG.forbiddenWords.filter(word => lowerPwd.includes(word));
  const forbiddenFound = matchedForbidden.length > 0;

  // Acceptance Criteria: all 5 rules must be satisfied
  const isAccepted = (
    isLengthValid &&
    uppCount >= 1 &&
    lowCount >= 1 &&
    digCount >= 1 &&
    specCount >= 1 &&
    !forbiddenFound
  );

  // Strength Evaluation:
  // Strong: min 2 characters each (Upper, Lower, Digit, Special)
  // High: min 1 character each AND at least 2 of either
  // Moderate: min 1 character each
  // Weak: does not contain min 1 each OR does not comply with policy 1 (length) and policy 5 (forbidden words)
  let strength = "Weak";

  if (!isLengthValid || forbiddenFound) {
    strength = "Weak";
  } else {
    const hasMin1Each = (uppCount >= 1 && lowCount >= 1 && digCount >= 1 && specCount >= 1);
    if (!hasMin1Each) {
      strength = "Weak";
    } else {
      const hasAll2 = (uppCount >= 2 && lowCount >= 2 && digCount >= 2 && specCount >= 2);
      const hasAny2 = (uppCount >= 2 || lowCount >= 2 || digCount >= 2 || specCount >= 2);

      if (hasAll2) {
        strength = "Strong";
      } else if (hasAny2) {
        strength = "High";
      } else {
        strength = "Moderate";
      }
    }
  }

  // Entropy Calculation (Shannon Entropy approximation)
  let poolSize = 0;
  if (uppCount > 0) poolSize += 26;
  if (lowCount > 0) poolSize += 26;
  if (digCount > 0) poolSize += 10;
  if (specCount > 0) poolSize += POLICY_CONFIG.specialChars.length;

  const entropy = poolSize > 0 && len > 0 ? (len * (Math.log2(poolSize))).toFixed(1) : "0.0";

  // Estimated crack time
  let crackTime = "Instant";
  const numEntropy = parseFloat(entropy);
  if (numEntropy <= 20) crackTime = "Instant";
  else if (numEntropy <= 35) crackTime = "< 1 minute";
  else if (numEntropy <= 45) crackTime = "3 hours";
  else if (numEntropy <= 55) crackTime = "4 months";
  else if (numEntropy <= 65) crackTime = "3,400 years";
  else crackTime = "120M+ years";

  return {
    password,
    len,
    isLengthValid,
    uppCount,
    lowCount,
    digCount,
    specCount,
    matchedSpecials,
    forbiddenFound,
    matchedForbidden,
    isAccepted,
    strength,
    entropy,
    crackTime
  };
}

/**
 * Update UI with analysis result
 */
function updateUI(res) {
  // Update char count and entropy
  charCountValue.textContent = `${res.len} chars`;
  entropyValue.textContent = `${res.entropy} bits`;
  crackTimeValue.textContent = res.crackTime;

  // 1. Acceptance Banner
  if (res.isAccepted) {
    acceptanceCard.className = "card verdict-card accepted";
    acceptanceBadge.textContent = "ACCEPTED";
    acceptanceDesc.textContent = "Complies with all 5 institutional security requirements!";
    acceptanceIcon.innerHTML = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
        <polyline points="22 4 12 14.01 9 11.01"/>
      </svg>
    `;
  } else {
    acceptanceCard.className = "card verdict-card rejected";
    acceptanceBadge.textContent = "REJECTED";
    acceptanceIcon.innerHTML = `
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <circle cx="12" cy="12" r="10"/>
        <line x1="15" y1="9" x2="9" y2="15"/>
        <line x1="9" y1="9" x2="15" y2="15"/>
      </svg>
    `;

    // Construct informative rejection reason
    const reasons = [];
    if (!res.isLengthValid) {
      if (res.len < POLICY_CONFIG.minLength) reasons.push(`Length too short (${res.len} < 8)`);
      else reasons.push(`Length too long (${res.len} > 14)`);
    }
    if (res.uppCount < 1) reasons.push("Missing uppercase");
    if (res.lowCount < 1) reasons.push("Missing lowercase");
    if (res.digCount < 1) reasons.push("Missing digit");
    if (res.specCount < 1) reasons.push("Missing special character");
    if (res.forbiddenFound) reasons.push(`Contains forbidden word: "${res.matchedForbidden.join(', ')}"`);

    acceptanceDesc.textContent = reasons.join(" • ") || "Security policy requirements not satisfied.";
  }

  // 2. Strength Card & Segments
  strengthCard.className = `card strength-card strength-${res.strength.toLowerCase()}`;
  strengthTitle.textContent = `Strength is ${res.strength}!`;
  strengthPill.textContent = res.strength;

  // Clear segment active classes
  [seg1, seg2, seg3, seg4].forEach(seg => {
    seg.className = "segment";
  });

  if (res.strength === "Weak") {
    seg1.classList.add("active-weak");
  } else if (res.strength === "Moderate") {
    seg1.classList.add("active-moderate");
    seg2.classList.add("active-moderate");
  } else if (res.strength === "High") {
    seg1.classList.add("active-high");
    seg2.classList.add("active-high");
    seg3.classList.add("active-high");
  } else if (res.strength === "Strong") {
    seg1.classList.add("active-strong");
    seg2.classList.add("active-strong");
    seg3.classList.add("active-strong");
    seg4.classList.add("active-strong");
  }

  // 3. Policy Checklist Cards
  // Policy 1: Length
  if (res.isLengthValid) {
    policyLengthCard.className = "card policy-card pass";
    statusLength.textContent = "PASS";
    fillLength.style.background = "var(--emerald-400)";
  } else {
    policyLengthCard.className = "card policy-card fail";
    statusLength.textContent = "FAIL";
    fillLength.style.background = "var(--rose-400)";
  }
  const pct = Math.min(100, Math.max(0, (res.len / POLICY_CONFIG.maxLength) * 100));
  fillLength.style.width = `${pct}%`;
  labelLengthCur.textContent = `${res.len} characters`;

  // Policy 2a: Uppercase
  countUpper.textContent = res.uppCount;
  if (res.uppCount >= 1) {
    policyUpperCard.className = "card policy-card pass";
    statusUpper.textContent = "PASS";
  } else {
    policyUpperCard.className = "card policy-card fail";
    statusUpper.textContent = "FAIL";
  }

  // Policy 2b: Lowercase
  countLower.textContent = res.lowCount;
  if (res.lowCount >= 1) {
    policyLowerCard.className = "card policy-card pass";
    statusLower.textContent = "PASS";
  } else {
    policyLowerCard.className = "card policy-card fail";
    statusLower.textContent = "FAIL";
  }

  // Policy 3: Digits
  countDigit.textContent = res.digCount;
  if (res.digCount >= 1) {
    policyDigitCard.className = "card policy-card pass";
    statusDigit.textContent = "PASS";
  } else {
    policyDigitCard.className = "card policy-card fail";
    statusDigit.textContent = "FAIL";
  }

  // Policy 4: Special Characters
  countSpec.textContent = res.specCount;
  if (res.specCount >= 1) {
    policySpecCard.className = "card policy-card pass";
    statusSpec.textContent = "PASS";
  } else {
    policySpecCard.className = "card policy-card fail";
    statusSpec.textContent = "FAIL";
  }
  specMatchedChars.textContent = res.matchedSpecials.length > 0 ? res.matchedSpecials.join(" ") : "None";

  // Policy 5: Forbidden Words
  if (!res.forbiddenFound) {
    policyForbiddenCard.className = "card policy-card pass";
    statusForbidden.textContent = "PASS";
    forbiddenAlert.innerHTML = `
      <span class="clean-tag" id="forbidden-clean-tag">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
        No forbidden words detected
      </span>
    `;
  } else {
    policyForbiddenCard.className = "card policy-card fail";
    statusForbidden.textContent = "FAIL";
    forbiddenAlert.innerHTML = `
      <span class="danger-tag">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
        Detected: "${res.matchedForbidden.join(', ')}"
      </span>
    `;
  }

  // 4. Matrix Active Tier Highlight
  [tierStrong, tierHigh, tierModerate, tierWeak].forEach(t => t.classList.remove("active"));
  if (res.strength === "Strong") tierStrong.classList.add("active");
  else if (res.strength === "High") tierHigh.classList.add("active");
  else if (res.strength === "Moderate") tierModerate.classList.add("active");
  else tierWeak.classList.add("active");

  // 5. Generate exact Python CLI output simulator
  updateTerminalSimulation(res);
}

/**
 * Updates the Terminal code block to replicate Password_Policy_And_Strength.py output
 */
function updateTerminalSimulation(res) {
  const lines = [];
  lines.push(`Please Enter your password: ${res.password}`);

  if (res.uppCount >= 1 && res.lowCount >= 1 && res.digCount >= 1 && res.specCount >= 1) {
    lines.push("All character requirements satisfied");
  }

  if (res.forbiddenFound) {
    lines.push("Password should not contain forbidden words.");
  }

  lines.push(`length_valid : ${res.isLengthValid ? "True, PASS" : "False, NOT PASS"}`);
  lines.push(`upp_count : ${res.uppCount}, ${res.uppCount >= 1 ? "PASS" : "NOT PASS"}`);
  lines.push(`low_count : ${res.lowCount}, ${res.lowCount >= 1 ? "PASS" : "NOT PASS"}`);
  lines.push(`dig_count : ${res.digCount}, ${res.digCount >= 1 ? "PASS" : "NOT PASS"}`);
  lines.push(`spec_count : ${res.specCount}, ${res.specCount >= 1 ? "PASS" : "NOT PASS"}`);
  lines.push(`Forbidden found : ${res.forbiddenFound}, ${!res.forbiddenFound ? "PASS" : "NOT PASS"}`);
  lines.push(`Password_Valid : ${res.isAccepted}, ${res.isAccepted ? "PASS" : "NOT PASS"}`);
  lines.push(`Strength is ${res.strength}!`);

  terminalOutput.innerHTML = `<code>${lines.join("\n")}</code>`;
}

/**
 * Policy-Compliant Password Generator
 */
function generateCompliantPassword(targetTier = "Strong", length = 12) {
  const uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lowers = "abcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const specials = "@#$%&*!";

  const getRandomChar = (str) => str[Math.floor(Math.random() * str.length)];

  let chars = [];

  if (targetTier === "Strong") {
    // Min 2 of each
    chars.push(getRandomChar(uppers), getRandomChar(uppers));
    chars.push(getRandomChar(lowers), getRandomChar(lowers));
    chars.push(getRandomChar(digits), getRandomChar(digits));
    chars.push(getRandomChar(specials), getRandomChar(specials));
  } else {
    // High: Min 1 of each + 1 extra
    chars.push(getRandomChar(uppers));
    chars.push(getRandomChar(lowers));
    chars.push(getRandomChar(digits));
    chars.push(getRandomChar(specials));
    chars.push(getRandomChar(uppers + lowers)); // at least 2 in one
  }

  // Fill remainder up to target length (between 8 and 14)
  const combined = uppers + lowers + digits + specials;
  while (chars.length < length) {
    chars.push(getRandomChar(combined));
  }

  // Shuffle array using Fisher-Yates
  for (let i = chars.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  let generated = chars.join("");

  // Double check forbidden words
  const lowerGen = generated.toLowerCase();
  for (const forbidden of POLICY_CONFIG.forbiddenWords) {
    if (lowerGen.includes(forbidden)) {
      return generateCompliantPassword(targetTier, length); // Re-roll
    }
  }

  return generated;
}

/**
 * Event Listeners & Initialization
 */
function init() {
  // 1. Password input event
  passwordInput.addEventListener("input", (e) => {
    const res = analyzePassword(e.target.value);
    updateUI(res);
  });

  // 2. Visibility toggle
  btnToggleVisibility.addEventListener("click", () => {
    const isPassword = passwordInput.getAttribute("type") === "password";
    passwordInput.setAttribute("type", isPassword ? "text" : "password");

    if (isPassword) {
      eyeIcon.innerHTML = `
        <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
        <line x1="1" y1="1" x2="23" y2="23"/>
      `;
      btnToggleVisibility.title = "Hide Password";
    } else {
      eyeIcon.innerHTML = `
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      `;
      btnToggleVisibility.title = "Show Password";
    }
  });

  // 3. Copy password
  btnCopyPassword.addEventListener("click", () => {
    if (!passwordInput.value) {
      showToast("Password field is empty", "info");
      return;
    }
    navigator.clipboard.writeText(passwordInput.value).then(() => {
      showToast("Password copied to clipboard!", "success");
    });
  });

  // 4. Clear password
  btnClearPassword.addEventListener("click", () => {
    passwordInput.value = "";
    passwordInput.focus();
    updateUI(analyzePassword(""));
  });

  // 5. Preset chips
  document.querySelectorAll(".preset-chip").forEach(chip => {
    chip.addEventListener("click", () => {
      const pwd = chip.getAttribute("data-pwd");
      passwordInput.value = pwd;
      updateUI(analyzePassword(pwd));
      showToast(`Loaded preset: "${pwd}"`, "info");
    });
  });

  // 6. Generator slider update
  genLengthSlider.addEventListener("input", (e) => {
    genLengthVal.textContent = e.target.value;
  });

  // 7. Generate password button
  btnGeneratePassword.addEventListener("click", () => {
    const length = parseInt(genLengthSlider.value, 10);
    const selectedTier = document.querySelector('input[name="gen-tier"]:checked')?.value || "Strong";
    const generated = generateCompliantPassword(selectedTier, length);

    passwordInput.value = generated;
    updateUI(analyzePassword(generated));
    showToast(`Generated ${selectedTier} password (${length} chars)!`, "success");
  });

  // 8. Toggle Generator scroll into view
  btnToggleGenerator.addEventListener("click", () => {
    generatorCard.scrollIntoView({ behavior: "smooth", block: "center" });
    generatorCard.style.boxShadow = "0 0 25px rgba(56, 189, 248, 0.4)";
    setTimeout(() => {
      generatorCard.style.boxShadow = "";
    }, 1200);
  });

  // 9. Copy CLI Output
  btnCopyTerminal.addEventListener("click", () => {
    const text = terminalOutput.innerText;
    navigator.clipboard.writeText(text).then(() => {
      showToast("Python CLI output copied!", "success");
    });
  });

  // 10. Export Full Markdown Audit Report
  btnCopyReport.addEventListener("click", () => {
    const res = analyzePassword(passwordInput.value);
    const report = `# Password Security & Policy Audit Report
- Target Password: \`${res.password}\`
- Policy Acceptance: **${res.isAccepted ? "ACCEPTED (PASS)" : "REJECTED (FAIL)"}**
- Strength Level: **${res.strength}**
- Calculated Entropy: **${res.entropy} bits**
- Estimated Crack Time: **${res.crackTime}**

### Policy Breakdown:
1. Length (8 to 14): ${res.len} characters — **${res.isLengthValid ? "PASS" : "FAIL"}**
2. Uppercase Letters: ${res.uppCount} — **${res.uppCount >= 1 ? "PASS" : "FAIL"}**
3. Lowercase Letters: ${res.lowCount} — **${res.lowCount >= 1 ? "PASS" : "FAIL"}**
4. Numerical Digits: ${res.digCount} — **${res.digCount >= 1 ? "PASS" : "FAIL"}**
5. Special Characters: ${res.specCount} — **${res.specCount >= 1 ? "PASS" : "FAIL"}**
6. Forbidden Words: ${res.forbiddenFound ? `Found ("${res.matchedForbidden.join(', ')}")` : "None"} — **${!res.forbiddenFound ? "PASS" : "FAIL"}**

*Generated by PassShield OOPS Security Engine*
`;
    navigator.clipboard.writeText(report).then(() => {
      showToast("Audit Report copied to clipboard in Markdown format!", "success");
    });
  });

  // Initial evaluation on load
  updateUI(analyzePassword(passwordInput.value));
}

// Start app
document.addEventListener("DOMContentLoaded", init);
