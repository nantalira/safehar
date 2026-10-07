// packages/safehar-core/src/exporter.ts
var DEFAULT_CREATOR = {
  name: "SafeHAR Sanitizer",
  version: "0.1.0",
  comment: "100% Client-side privacy-first sanitized HAR export"
};
function* generateSanitizedHarChunks(metadata, sanitizedEntries) {
  const header = {
    version: metadata.version || "1.2",
    creator: metadata.creator || DEFAULT_CREATOR,
    browser: metadata.browser,
    pages: metadata.pages || []
  };
  yield `{
  "log": {
    "version": ${JSON.stringify(header.version)},
    "creator": ${JSON.stringify(header.creator)},
`;
  if (header.browser) {
    yield `    "browser": ${JSON.stringify(header.browser)},
`;
  }
  if (header.pages && header.pages.length > 0) {
    yield `    "pages": ${JSON.stringify(header.pages)},
`;
  }
  yield `    "entries": [
`;
  for (let i = 0;i < sanitizedEntries.length; i++) {
    const entryJson = JSON.stringify(sanitizedEntries[i]);
    const isLast = i === sanitizedEntries.length - 1;
    yield `      ${entryJson}${isLast ? "" : `,
`}`;
  }
  yield `
    ]
  }
}`;
}
// packages/safehar-core/src/sanitizer.ts
var DEFAULT_REDACTION_OPTIONS = {
  maskAuthHeaders: true,
  maskCookies: true,
  maskStripeKeys: true,
  maskAwsKeys: true,
  maskEmails: true,
  maskCreditCards: true
};
var REGEX_STAGE_1_JWT = /Bearer\s+ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g;
var REGEX_STAGE_2_BASIC = /Basic\s+[A-Za-z0-9+/=]{10,}/g;
var REGEX_STAGE_3_SESSION_COOKIES = /(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|connect\.sid)=[^;]+/gi;
var REGEX_STAGE_4_OAUTH = /(access_token|refresh_token|client_secret)=([A-Za-z0-9\-_.~+/%]{16,})/gi;
var REGEX_STAGE_5_STRIPE = /(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}/g;
var REGEX_STAGE_6_AWS = /(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])/g;
var REGEX_STAGE_7_GITHUB = /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g;
var REGEX_STAGE_8_EMAIL = /[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+/g;
var REGEX_STAGE_9_CARD = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g;
function sanitizeString(input, options = DEFAULT_REDACTION_OPTIONS) {
  if (!input || typeof input !== "string") {
    return { text: input, redactedCount: 0, hasSensitiveAuth: false };
  }
  let text = input;
  let count = 0;
  let hasSensitiveAuth = false;
  const countMatches = (regex, str) => {
    const matches = str.match(regex);
    return matches ? matches.length : 0;
  };
  if (options.maskAuthHeaders) {
    const matches = countMatches(REGEX_STAGE_1_JWT, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_1_JWT, "Bearer [REDACTED_JWT_TOKEN]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }
  if (options.maskAuthHeaders) {
    const matches = countMatches(REGEX_STAGE_2_BASIC, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_2_BASIC, "Basic [REDACTED_BASIC_AUTH]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }
  if (options.maskCookies) {
    const matches = countMatches(REGEX_STAGE_3_SESSION_COOKIES, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_3_SESSION_COOKIES, "$1=[REDACTED_SESSION_ID]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }
  const oauthMatches = countMatches(REGEX_STAGE_4_OAUTH, text);
  if (oauthMatches > 0) {
    text = text.replace(REGEX_STAGE_4_OAUTH, "$1=[REDACTED_OAUTH_TOKEN]");
    count += oauthMatches;
    hasSensitiveAuth = true;
  }
  if (options.maskStripeKeys) {
    const matches = countMatches(REGEX_STAGE_5_STRIPE, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_5_STRIPE, "[REDACTED_STRIPE_SECRET_KEY]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }
  if (options.maskAwsKeys) {
    const matches = countMatches(REGEX_STAGE_6_AWS, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_6_AWS, "[REDACTED_AWS_ACCESS_KEY]");
      count += matches;
      hasSensitiveAuth = true;
    }
  }
  const ghMatches = countMatches(REGEX_STAGE_7_GITHUB, text);
  if (ghMatches > 0) {
    text = text.replace(REGEX_STAGE_7_GITHUB, "[REDACTED_GITHUB_TOKEN]");
    count += ghMatches;
    hasSensitiveAuth = true;
  }
  if (options.maskEmails) {
    const matches = countMatches(REGEX_STAGE_8_EMAIL, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_8_EMAIL, "[REDACTED_EMAIL_ADDRESS]");
      count += matches;
    }
  }
  if (options.maskCreditCards) {
    const matches = countMatches(REGEX_STAGE_9_CARD, text);
    if (matches > 0) {
      text = text.replace(REGEX_STAGE_9_CARD, "[REDACTED_PAYMENT_CARD]");
      count += matches;
    }
  }
  return { text, redactedCount: count, hasSensitiveAuth };
}
function sanitizeEntry(entry, index, options = DEFAULT_REDACTION_OPTIONS) {
  const cloned = structuredClone ? structuredClone(entry) : JSON.parse(JSON.stringify(entry));
  let totalRedacted = 0;
  let hasSensitiveAuth = false;
  const sanitizeField = (val) => {
    const res = sanitizeString(val, options);
    totalRedacted += res.redactedCount;
    if (res.hasSensitiveAuth)
      hasSensitiveAuth = true;
    return res.text;
  };
  if (cloned.request) {
    if (cloned.request.url) {
      cloned.request.url = sanitizeField(cloned.request.url);
    }
    if (Array.isArray(cloned.request.queryString)) {
      for (const q of cloned.request.queryString) {
        if (q.value)
          q.value = sanitizeField(q.value);
      }
    }
    if (Array.isArray(cloned.request.headers)) {
      for (const h of cloned.request.headers) {
        if (h.value)
          h.value = sanitizeField(h.value);
      }
    }
    if (Array.isArray(cloned.request.cookies)) {
      for (const c of cloned.request.cookies) {
        if (options.maskCookies) {
          const cookieName = c.name?.toLowerCase?.() || "";
          if (["phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"].includes(cookieName)) {
            c.value = "[REDACTED_SESSION_ID]";
            totalRedacted++;
            hasSensitiveAuth = true;
          } else if (c.value) {
            c.value = sanitizeField(c.value);
          }
        }
      }
    }
    if (cloned.request.postData?.text) {
      cloned.request.postData.text = sanitizeField(cloned.request.postData.text);
    }
  }
  if (cloned.response) {
    if (Array.isArray(cloned.response.headers)) {
      for (const h of cloned.response.headers) {
        if (h.value)
          h.value = sanitizeField(h.value);
      }
    }
    if (Array.isArray(cloned.response.cookies)) {
      for (const c of cloned.response.cookies) {
        if (options.maskCookies) {
          const cookieName = c.name?.toLowerCase?.() || "";
          if (["phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid"].includes(cookieName)) {
            c.value = "[REDACTED_SESSION_ID]";
            totalRedacted++;
            hasSensitiveAuth = true;
          } else if (c.value) {
            c.value = sanitizeField(c.value);
          }
        }
      }
    }
    if (cloned.response.content?.text) {
      cloned.response.content.text = sanitizeField(cloned.response.content.text);
    }
  }
  const method = cloned.request?.method || "GET";
  const url = cloned.request?.url || `unknown-entry-${index}`;
  const status = cloned.response?.status || 0;
  const summary = {
    id: `entry_${index}_${Date.now()}`,
    method,
    url,
    status,
    redactedFieldsCount: totalRedacted,
    hasSensitiveAuth
  };
  return { sanitizedEntry: cloned, summary };
}
// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/utils/bufferedString.js
class NonBufferedString {
  constructor() {
    this.decoder = new TextDecoder("utf-8", { fatal: true });
    this.pending = [];
    this.string = "";
    this.byteLength = 0;
  }
  appendChar(char) {
    this.pending.push(String.fromCharCode(char));
    this.byteLength += 1;
  }
  appendBuf(buf, start = 0, end = buf.length) {
    this.pending.push(this.decoder.decode(buf.subarray(start, end)));
    this.byteLength += end - start;
  }
  appendCharCode(code) {
    this.pending.push(String.fromCharCode(code));
  }
  reset() {
    this.pending = [];
    this.string = "";
    this.byteLength = 0;
  }
  toString() {
    if (this.pending.length > 0) {
      this.string += this.pending.join("");
      this.pending = [];
    }
    return this.string;
  }
}

class BufferedString {
  constructor(bufferSize) {
    this.decoder = new TextDecoder("utf-8", { fatal: true });
    this.bufferOffset = 0;
    this.string = "";
    this.byteLength = 0;
    this.buffer = new Uint8Array(bufferSize);
  }
  appendChar(char) {
    if (this.bufferOffset >= this.buffer.length)
      this.flushStringBuffer();
    this.buffer[this.bufferOffset++] = char;
    this.byteLength += 1;
  }
  appendBuf(buf, start = 0, end = buf.length) {
    const size = end - start;
    if (this.bufferOffset + size > this.buffer.length)
      this.flushStringBuffer();
    if (size > this.buffer.length) {
      this.string += this.decoder.decode(buf.subarray(start, end));
      this.byteLength += size;
      return;
    }
    this.buffer.set(buf.subarray(start, end), this.bufferOffset);
    this.bufferOffset += size;
    this.byteLength += size;
  }
  appendCharCode(code) {
    this.flushStringBuffer();
    this.string += String.fromCharCode(code);
  }
  flushStringBuffer() {
    this.string += this.decoder.decode(this.buffer.subarray(0, this.bufferOffset));
    this.bufferOffset = 0;
  }
  reset() {
    this.string = "";
    this.bufferOffset = 0;
    this.byteLength = 0;
  }
  toString() {
    this.flushStringBuffer();
    return this.string;
  }
}

// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/utils/types/tokenType.js
var TokenType;
(function(TokenType2) {
  TokenType2[TokenType2["LEFT_BRACE"] = 0] = "LEFT_BRACE";
  TokenType2[TokenType2["RIGHT_BRACE"] = 1] = "RIGHT_BRACE";
  TokenType2[TokenType2["LEFT_BRACKET"] = 2] = "LEFT_BRACKET";
  TokenType2[TokenType2["RIGHT_BRACKET"] = 3] = "RIGHT_BRACKET";
  TokenType2[TokenType2["COLON"] = 4] = "COLON";
  TokenType2[TokenType2["COMMA"] = 5] = "COMMA";
  TokenType2[TokenType2["TRUE"] = 6] = "TRUE";
  TokenType2[TokenType2["FALSE"] = 7] = "FALSE";
  TokenType2[TokenType2["NULL"] = 8] = "NULL";
  TokenType2[TokenType2["STRING"] = 9] = "STRING";
  TokenType2[TokenType2["NUMBER"] = 10] = "NUMBER";
  TokenType2[TokenType2["SEPARATOR"] = 11] = "SEPARATOR";
})(TokenType || (TokenType = {}));
var tokenType_default = TokenType;

// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/utils/utf-8.js
var charset;
(function(charset2) {
  charset2[charset2["BACKSPACE"] = 8] = "BACKSPACE";
  charset2[charset2["FORM_FEED"] = 12] = "FORM_FEED";
  charset2[charset2["NEWLINE"] = 10] = "NEWLINE";
  charset2[charset2["CARRIAGE_RETURN"] = 13] = "CARRIAGE_RETURN";
  charset2[charset2["TAB"] = 9] = "TAB";
  charset2[charset2["SPACE"] = 32] = "SPACE";
  charset2[charset2["EXCLAMATION_MARK"] = 33] = "EXCLAMATION_MARK";
  charset2[charset2["QUOTATION_MARK"] = 34] = "QUOTATION_MARK";
  charset2[charset2["NUMBER_SIGN"] = 35] = "NUMBER_SIGN";
  charset2[charset2["DOLLAR_SIGN"] = 36] = "DOLLAR_SIGN";
  charset2[charset2["PERCENT_SIGN"] = 37] = "PERCENT_SIGN";
  charset2[charset2["AMPERSAND"] = 38] = "AMPERSAND";
  charset2[charset2["APOSTROPHE"] = 39] = "APOSTROPHE";
  charset2[charset2["LEFT_PARENTHESIS"] = 40] = "LEFT_PARENTHESIS";
  charset2[charset2["RIGHT_PARENTHESIS"] = 41] = "RIGHT_PARENTHESIS";
  charset2[charset2["ASTERISK"] = 42] = "ASTERISK";
  charset2[charset2["PLUS_SIGN"] = 43] = "PLUS_SIGN";
  charset2[charset2["COMMA"] = 44] = "COMMA";
  charset2[charset2["HYPHEN_MINUS"] = 45] = "HYPHEN_MINUS";
  charset2[charset2["FULL_STOP"] = 46] = "FULL_STOP";
  charset2[charset2["SOLIDUS"] = 47] = "SOLIDUS";
  charset2[charset2["DIGIT_ZERO"] = 48] = "DIGIT_ZERO";
  charset2[charset2["DIGIT_ONE"] = 49] = "DIGIT_ONE";
  charset2[charset2["DIGIT_TWO"] = 50] = "DIGIT_TWO";
  charset2[charset2["DIGIT_THREE"] = 51] = "DIGIT_THREE";
  charset2[charset2["DIGIT_FOUR"] = 52] = "DIGIT_FOUR";
  charset2[charset2["DIGIT_FIVE"] = 53] = "DIGIT_FIVE";
  charset2[charset2["DIGIT_SIX"] = 54] = "DIGIT_SIX";
  charset2[charset2["DIGIT_SEVEN"] = 55] = "DIGIT_SEVEN";
  charset2[charset2["DIGIT_EIGHT"] = 56] = "DIGIT_EIGHT";
  charset2[charset2["DIGIT_NINE"] = 57] = "DIGIT_NINE";
  charset2[charset2["COLON"] = 58] = "COLON";
  charset2[charset2["SEMICOLON"] = 59] = "SEMICOLON";
  charset2[charset2["LESS_THAN_SIGN"] = 60] = "LESS_THAN_SIGN";
  charset2[charset2["EQUALS_SIGN"] = 61] = "EQUALS_SIGN";
  charset2[charset2["GREATER_THAN_SIGN"] = 62] = "GREATER_THAN_SIGN";
  charset2[charset2["QUESTION_MARK"] = 63] = "QUESTION_MARK";
  charset2[charset2["COMMERCIAL_AT"] = 64] = "COMMERCIAL_AT";
  charset2[charset2["LATIN_CAPITAL_LETTER_A"] = 65] = "LATIN_CAPITAL_LETTER_A";
  charset2[charset2["LATIN_CAPITAL_LETTER_B"] = 66] = "LATIN_CAPITAL_LETTER_B";
  charset2[charset2["LATIN_CAPITAL_LETTER_C"] = 67] = "LATIN_CAPITAL_LETTER_C";
  charset2[charset2["LATIN_CAPITAL_LETTER_D"] = 68] = "LATIN_CAPITAL_LETTER_D";
  charset2[charset2["LATIN_CAPITAL_LETTER_E"] = 69] = "LATIN_CAPITAL_LETTER_E";
  charset2[charset2["LATIN_CAPITAL_LETTER_F"] = 70] = "LATIN_CAPITAL_LETTER_F";
  charset2[charset2["LATIN_CAPITAL_LETTER_G"] = 71] = "LATIN_CAPITAL_LETTER_G";
  charset2[charset2["LATIN_CAPITAL_LETTER_H"] = 72] = "LATIN_CAPITAL_LETTER_H";
  charset2[charset2["LATIN_CAPITAL_LETTER_I"] = 73] = "LATIN_CAPITAL_LETTER_I";
  charset2[charset2["LATIN_CAPITAL_LETTER_J"] = 74] = "LATIN_CAPITAL_LETTER_J";
  charset2[charset2["LATIN_CAPITAL_LETTER_K"] = 75] = "LATIN_CAPITAL_LETTER_K";
  charset2[charset2["LATIN_CAPITAL_LETTER_L"] = 76] = "LATIN_CAPITAL_LETTER_L";
  charset2[charset2["LATIN_CAPITAL_LETTER_M"] = 77] = "LATIN_CAPITAL_LETTER_M";
  charset2[charset2["LATIN_CAPITAL_LETTER_N"] = 78] = "LATIN_CAPITAL_LETTER_N";
  charset2[charset2["LATIN_CAPITAL_LETTER_O"] = 79] = "LATIN_CAPITAL_LETTER_O";
  charset2[charset2["LATIN_CAPITAL_LETTER_P"] = 80] = "LATIN_CAPITAL_LETTER_P";
  charset2[charset2["LATIN_CAPITAL_LETTER_Q"] = 81] = "LATIN_CAPITAL_LETTER_Q";
  charset2[charset2["LATIN_CAPITAL_LETTER_R"] = 82] = "LATIN_CAPITAL_LETTER_R";
  charset2[charset2["LATIN_CAPITAL_LETTER_S"] = 83] = "LATIN_CAPITAL_LETTER_S";
  charset2[charset2["LATIN_CAPITAL_LETTER_T"] = 84] = "LATIN_CAPITAL_LETTER_T";
  charset2[charset2["LATIN_CAPITAL_LETTER_U"] = 85] = "LATIN_CAPITAL_LETTER_U";
  charset2[charset2["LATIN_CAPITAL_LETTER_V"] = 86] = "LATIN_CAPITAL_LETTER_V";
  charset2[charset2["LATIN_CAPITAL_LETTER_W"] = 87] = "LATIN_CAPITAL_LETTER_W";
  charset2[charset2["LATIN_CAPITAL_LETTER_X"] = 88] = "LATIN_CAPITAL_LETTER_X";
  charset2[charset2["LATIN_CAPITAL_LETTER_Y"] = 89] = "LATIN_CAPITAL_LETTER_Y";
  charset2[charset2["LATIN_CAPITAL_LETTER_Z"] = 90] = "LATIN_CAPITAL_LETTER_Z";
  charset2[charset2["LEFT_SQUARE_BRACKET"] = 91] = "LEFT_SQUARE_BRACKET";
  charset2[charset2["REVERSE_SOLIDUS"] = 92] = "REVERSE_SOLIDUS";
  charset2[charset2["RIGHT_SQUARE_BRACKET"] = 93] = "RIGHT_SQUARE_BRACKET";
  charset2[charset2["CIRCUMFLEX_ACCENT"] = 94] = "CIRCUMFLEX_ACCENT";
  charset2[charset2["LOW_LINE"] = 95] = "LOW_LINE";
  charset2[charset2["GRAVE_ACCENT"] = 96] = "GRAVE_ACCENT";
  charset2[charset2["LATIN_SMALL_LETTER_A"] = 97] = "LATIN_SMALL_LETTER_A";
  charset2[charset2["LATIN_SMALL_LETTER_B"] = 98] = "LATIN_SMALL_LETTER_B";
  charset2[charset2["LATIN_SMALL_LETTER_C"] = 99] = "LATIN_SMALL_LETTER_C";
  charset2[charset2["LATIN_SMALL_LETTER_D"] = 100] = "LATIN_SMALL_LETTER_D";
  charset2[charset2["LATIN_SMALL_LETTER_E"] = 101] = "LATIN_SMALL_LETTER_E";
  charset2[charset2["LATIN_SMALL_LETTER_F"] = 102] = "LATIN_SMALL_LETTER_F";
  charset2[charset2["LATIN_SMALL_LETTER_G"] = 103] = "LATIN_SMALL_LETTER_G";
  charset2[charset2["LATIN_SMALL_LETTER_H"] = 104] = "LATIN_SMALL_LETTER_H";
  charset2[charset2["LATIN_SMALL_LETTER_I"] = 105] = "LATIN_SMALL_LETTER_I";
  charset2[charset2["LATIN_SMALL_LETTER_J"] = 106] = "LATIN_SMALL_LETTER_J";
  charset2[charset2["LATIN_SMALL_LETTER_K"] = 107] = "LATIN_SMALL_LETTER_K";
  charset2[charset2["LATIN_SMALL_LETTER_L"] = 108] = "LATIN_SMALL_LETTER_L";
  charset2[charset2["LATIN_SMALL_LETTER_M"] = 109] = "LATIN_SMALL_LETTER_M";
  charset2[charset2["LATIN_SMALL_LETTER_N"] = 110] = "LATIN_SMALL_LETTER_N";
  charset2[charset2["LATIN_SMALL_LETTER_O"] = 111] = "LATIN_SMALL_LETTER_O";
  charset2[charset2["LATIN_SMALL_LETTER_P"] = 112] = "LATIN_SMALL_LETTER_P";
  charset2[charset2["LATIN_SMALL_LETTER_Q"] = 113] = "LATIN_SMALL_LETTER_Q";
  charset2[charset2["LATIN_SMALL_LETTER_R"] = 114] = "LATIN_SMALL_LETTER_R";
  charset2[charset2["LATIN_SMALL_LETTER_S"] = 115] = "LATIN_SMALL_LETTER_S";
  charset2[charset2["LATIN_SMALL_LETTER_T"] = 116] = "LATIN_SMALL_LETTER_T";
  charset2[charset2["LATIN_SMALL_LETTER_U"] = 117] = "LATIN_SMALL_LETTER_U";
  charset2[charset2["LATIN_SMALL_LETTER_V"] = 118] = "LATIN_SMALL_LETTER_V";
  charset2[charset2["LATIN_SMALL_LETTER_W"] = 119] = "LATIN_SMALL_LETTER_W";
  charset2[charset2["LATIN_SMALL_LETTER_X"] = 120] = "LATIN_SMALL_LETTER_X";
  charset2[charset2["LATIN_SMALL_LETTER_Y"] = 121] = "LATIN_SMALL_LETTER_Y";
  charset2[charset2["LATIN_SMALL_LETTER_Z"] = 122] = "LATIN_SMALL_LETTER_Z";
  charset2[charset2["LEFT_CURLY_BRACKET"] = 123] = "LEFT_CURLY_BRACKET";
  charset2[charset2["VERTICAL_LINE"] = 124] = "VERTICAL_LINE";
  charset2[charset2["RIGHT_CURLY_BRACKET"] = 125] = "RIGHT_CURLY_BRACKET";
  charset2[charset2["TILDE"] = 126] = "TILDE";
})(charset || (charset = {}));
var escapedSequences = {
  [34]: 34,
  [92]: 92,
  [47]: 47,
  [98]: 8,
  [102]: 12,
  [110]: 10,
  [114]: 13,
  [116]: 9
};

// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/tokenizer.js
var TokenizerStates;
(function(TokenizerStates2) {
  TokenizerStates2[TokenizerStates2["START"] = 0] = "START";
  TokenizerStates2[TokenizerStates2["ENDED"] = 1] = "ENDED";
  TokenizerStates2[TokenizerStates2["ERROR"] = 2] = "ERROR";
  TokenizerStates2[TokenizerStates2["TRUE1"] = 3] = "TRUE1";
  TokenizerStates2[TokenizerStates2["TRUE2"] = 4] = "TRUE2";
  TokenizerStates2[TokenizerStates2["TRUE3"] = 5] = "TRUE3";
  TokenizerStates2[TokenizerStates2["FALSE1"] = 6] = "FALSE1";
  TokenizerStates2[TokenizerStates2["FALSE2"] = 7] = "FALSE2";
  TokenizerStates2[TokenizerStates2["FALSE3"] = 8] = "FALSE3";
  TokenizerStates2[TokenizerStates2["FALSE4"] = 9] = "FALSE4";
  TokenizerStates2[TokenizerStates2["NULL1"] = 10] = "NULL1";
  TokenizerStates2[TokenizerStates2["NULL2"] = 11] = "NULL2";
  TokenizerStates2[TokenizerStates2["NULL3"] = 12] = "NULL3";
  TokenizerStates2[TokenizerStates2["STRING_DEFAULT"] = 13] = "STRING_DEFAULT";
  TokenizerStates2[TokenizerStates2["STRING_AFTER_BACKSLASH"] = 14] = "STRING_AFTER_BACKSLASH";
  TokenizerStates2[TokenizerStates2["STRING_UNICODE_DIGIT_1"] = 15] = "STRING_UNICODE_DIGIT_1";
  TokenizerStates2[TokenizerStates2["STRING_UNICODE_DIGIT_2"] = 16] = "STRING_UNICODE_DIGIT_2";
  TokenizerStates2[TokenizerStates2["STRING_UNICODE_DIGIT_3"] = 17] = "STRING_UNICODE_DIGIT_3";
  TokenizerStates2[TokenizerStates2["STRING_UNICODE_DIGIT_4"] = 18] = "STRING_UNICODE_DIGIT_4";
  TokenizerStates2[TokenizerStates2["STRING_INCOMPLETE_CHAR"] = 19] = "STRING_INCOMPLETE_CHAR";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_INITIAL_MINUS"] = 20] = "NUMBER_AFTER_INITIAL_MINUS";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_INITIAL_ZERO"] = 21] = "NUMBER_AFTER_INITIAL_ZERO";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_INITIAL_NON_ZERO"] = 22] = "NUMBER_AFTER_INITIAL_NON_ZERO";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_FULL_STOP"] = 23] = "NUMBER_AFTER_FULL_STOP";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_DECIMAL"] = 24] = "NUMBER_AFTER_DECIMAL";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_E"] = 25] = "NUMBER_AFTER_E";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_E_AND_SIGN"] = 26] = "NUMBER_AFTER_E_AND_SIGN";
  TokenizerStates2[TokenizerStates2["NUMBER_AFTER_E_AND_DIGIT"] = 27] = "NUMBER_AFTER_E_AND_DIGIT";
  TokenizerStates2[TokenizerStates2["SEPARATOR"] = 28] = "SEPARATOR";
  TokenizerStates2[TokenizerStates2["BOM_OR_START"] = 29] = "BOM_OR_START";
  TokenizerStates2[TokenizerStates2["BOM"] = 30] = "BOM";
})(TokenizerStates || (TokenizerStates = {}));
function TokenizerStateToString(tokenizerState) {
  return [
    "START",
    "ENDED",
    "ERROR",
    "TRUE1",
    "TRUE2",
    "TRUE3",
    "FALSE1",
    "FALSE2",
    "FALSE3",
    "FALSE4",
    "NULL1",
    "NULL2",
    "NULL3",
    "STRING_DEFAULT",
    "STRING_AFTER_BACKSLASH",
    "STRING_UNICODE_DIGIT_1",
    "STRING_UNICODE_DIGIT_2",
    "STRING_UNICODE_DIGIT_3",
    "STRING_UNICODE_DIGIT_4",
    "STRING_INCOMPLETE_CHAR",
    "NUMBER_AFTER_INITIAL_MINUS",
    "NUMBER_AFTER_INITIAL_ZERO",
    "NUMBER_AFTER_INITIAL_NON_ZERO",
    "NUMBER_AFTER_FULL_STOP",
    "NUMBER_AFTER_DECIMAL",
    "NUMBER_AFTER_E",
    "NUMBER_AFTER_E_AND_SIGN",
    "NUMBER_AFTER_E_AND_DIGIT",
    "SEPARATOR",
    "BOM_OR_START",
    "BOM"
  ][tokenizerState];
}
var defaultOpts = {
  stringBufferSize: 0,
  numberBufferSize: 0,
  separator: undefined,
  emitPartialTokens: false
};

class TokenizerError extends Error {
  constructor(message) {
    super(message);
    Object.setPrototypeOf(this, TokenizerError.prototype);
  }
}
function validateBufferSize(name, size) {
  if (size === undefined)
    return;
  if (!Number.isInteger(size) || size < 0) {
    throw new TokenizerError(`Invalid "${name}": ${size}. Expected a non-negative integer.`);
  }
}
function utf8SequenceLength(leadByte) {
  if (leadByte >= 194 && leadByte <= 223)
    return 2;
  if (leadByte <= 239)
    return 3;
  return 4;
}
function multiByteRunEnd(buffer, start) {
  let j = start;
  while (j < buffer.length && buffer[j] >= 128) {
    const seqLength = utf8SequenceLength(buffer[j]);
    if (j + seqLength > buffer.length)
      break;
    j += seqLength;
  }
  return j;
}

class Tokenizer {
  constructor(opts) {
    this.state = 29;
    this.bomIndex = 0;
    this.separatorIndex = 0;
    this.escapedCharsByteLength = 0;
    this.bytes_remaining = 0;
    this.bytes_in_sequence = 0;
    this.char_split_buffer = new Uint8Array(4);
    this.encoder = new TextEncoder;
    this.offset = -1;
    this.streamByteLength = 0;
    opts = Object.assign(Object.assign({}, defaultOpts), opts);
    validateBufferSize("stringBufferSize", opts.stringBufferSize);
    validateBufferSize("numberBufferSize", opts.numberBufferSize);
    this.emitPartialTokens = opts.emitPartialTokens === true;
    this.bufferedString = opts.stringBufferSize && opts.stringBufferSize > 4 ? new BufferedString(opts.stringBufferSize) : new NonBufferedString;
    this.bufferedNumber = opts.numberBufferSize && opts.numberBufferSize > 0 ? new BufferedString(opts.numberBufferSize) : new NonBufferedString;
    this.separator = opts.separator;
    this.separatorBytes = opts.separator ? this.encoder.encode(opts.separator) : undefined;
  }
  get isEnded() {
    return this.state === 1;
  }
  appendUnicodeCodeUnit(intVal) {
    if (this.highSurrogate !== undefined) {
      if (intVal >= 56320 && intVal <= 57343) {
        const unicodeString2 = String.fromCharCode(this.highSurrogate, intVal);
        const unicodeBuffer2 = this.encoder.encode(unicodeString2);
        this.bufferedString.appendBuf(unicodeBuffer2);
        this.escapedCharsByteLength += 6 - unicodeBuffer2.byteLength;
        this.highSurrogate = undefined;
        return;
      }
      this.flushPendingHighSurrogate();
    }
    if (intVal >= 55296 && intVal <= 56319) {
      this.highSurrogate = intVal;
      this.escapedCharsByteLength += 6;
      return;
    }
    if (intVal >= 56320 && intVal <= 57343) {
      this.bufferedString.appendCharCode(intVal);
      this.escapedCharsByteLength += 6;
      return;
    }
    const unicodeString = String.fromCharCode(intVal);
    const unicodeBuffer = this.encoder.encode(unicodeString);
    this.bufferedString.appendBuf(unicodeBuffer);
    this.escapedCharsByteLength += 6 - unicodeBuffer.byteLength;
  }
  flushPendingHighSurrogate() {
    if (this.highSurrogate !== undefined) {
      this.bufferedString.appendCharCode(this.highSurrogate);
      this.highSurrogate = undefined;
    }
  }
  startIncompleteChar(buffer, start) {
    this.bytes_in_sequence = utf8SequenceLength(buffer[start]);
    this.bytes_remaining = start + this.bytes_in_sequence - buffer.length;
    this.char_split_buffer.set(buffer.subarray(start));
    this.state = 19;
  }
  write(input) {
    try {
      let buffer;
      if (input instanceof Uint8Array) {
        buffer = input;
      } else if (typeof input === "string") {
        if (this.pendingStringSurrogate !== undefined) {
          input = this.pendingStringSurrogate + input;
          this.pendingStringSurrogate = undefined;
        }
        const lastCharCode = input.charCodeAt(input.length - 1);
        if (lastCharCode >= 55296 && lastCharCode <= 56319) {
          this.pendingStringSurrogate = input[input.length - 1];
          input = input.slice(0, -1);
        }
        buffer = this.encoder.encode(input);
      } else if (ArrayBuffer.isView(input)) {
        buffer = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
      } else if (input !== null && typeof input === "object" && typeof input[Symbol.iterator] === "function") {
        buffer = Uint8Array.from(input);
      } else {
        throw new TypeError("Unexpected type. The `write` function only accepts Iterables (e.g. Arrays, Sets, Generators), TypedArrays and Strings.");
      }
      for (let i = 0;i < buffer.length; i += 1) {
        const n = buffer[i];
        switch (this.state) {
          case 29:
            if (n === 239) {
              this.bom = [239, 187, 191];
              this.bomIndex += 1;
              this.state = 30;
              continue;
            }
            if (input instanceof Uint16Array) {
              if (n === 254) {
                this.bom = [254, 255];
                this.bomIndex += 1;
                this.state = 30;
                continue;
              }
              if (n === 255) {
                this.bom = [255, 254];
                this.bomIndex += 1;
                this.state = 30;
                continue;
              }
            }
            if (input instanceof Uint32Array) {
              if (n === 0) {
                this.bom = [0, 0, 254, 255];
                this.bomIndex += 1;
                this.state = 30;
                continue;
              }
              if (n === 255) {
                this.bom = [255, 254, 0, 0];
                this.bomIndex += 1;
                this.state = 30;
                continue;
              }
            }
          case 0:
            this.offset += 1;
            if (this.separatorBytes && n === this.separatorBytes[0]) {
              if (this.separatorBytes.length === 1) {
                this.state = 0;
                this.onToken({
                  token: tokenType_default.SEPARATOR,
                  value: this.separator,
                  offset: this.offset + this.separatorBytes.length - 1
                });
                continue;
              }
              this.state = 28;
              continue;
            }
            if (n === 32 || n === 10 || n === 13 || n === 9) {
              continue;
            }
            if (n === 123) {
              this.onToken({
                token: tokenType_default.LEFT_BRACE,
                value: "{",
                offset: this.offset
              });
              continue;
            }
            if (n === 125) {
              this.onToken({
                token: tokenType_default.RIGHT_BRACE,
                value: "}",
                offset: this.offset
              });
              continue;
            }
            if (n === 91) {
              this.onToken({
                token: tokenType_default.LEFT_BRACKET,
                value: "[",
                offset: this.offset
              });
              continue;
            }
            if (n === 93) {
              this.onToken({
                token: tokenType_default.RIGHT_BRACKET,
                value: "]",
                offset: this.offset
              });
              continue;
            }
            if (n === 58) {
              this.onToken({
                token: tokenType_default.COLON,
                value: ":",
                offset: this.offset
              });
              continue;
            }
            if (n === 44) {
              this.onToken({
                token: tokenType_default.COMMA,
                value: ",",
                offset: this.offset
              });
              continue;
            }
            if (n === 116) {
              this.state = 3;
              continue;
            }
            if (n === 102) {
              this.state = 6;
              continue;
            }
            if (n === 110) {
              this.state = 10;
              continue;
            }
            if (n === 34) {
              this.bufferedString.reset();
              this.escapedCharsByteLength = 0;
              this.state = 13;
              continue;
            }
            if (n >= 49 && n <= 57) {
              this.bufferedNumber.reset();
              this.bufferedNumber.appendChar(n);
              this.state = 22;
              continue;
            }
            if (n === 48) {
              this.bufferedNumber.reset();
              this.bufferedNumber.appendChar(n);
              this.state = 21;
              continue;
            }
            if (n === 45) {
              this.bufferedNumber.reset();
              this.bufferedNumber.appendChar(n);
              this.state = 20;
              continue;
            }
            break;
          case 13:
            if (n === 34) {
              this.flushPendingHighSurrogate();
              const string = this.bufferedString.toString();
              this.state = 0;
              this.onToken({
                token: tokenType_default.STRING,
                value: string,
                offset: this.offset
              });
              this.offset += this.escapedCharsByteLength + this.bufferedString.byteLength + 1;
              continue;
            }
            if (n === 92) {
              this.state = 14;
              continue;
            }
            if (n >= 128) {
              this.flushPendingHighSurrogate();
              const runEnd = multiByteRunEnd(buffer, i);
              if (runEnd > i) {
                this.bufferedString.appendBuf(buffer, i, runEnd);
                i = runEnd - 1;
              }
              if (runEnd < buffer.length && buffer[runEnd] >= 128) {
                this.startIncompleteChar(buffer, runEnd);
                i = buffer.length - 1;
              }
              continue;
            }
            if (n >= 32) {
              this.flushPendingHighSurrogate();
              let j = i;
              while (j < buffer.length) {
                const b = buffer[j];
                if (b < 32 || b >= 128 || b === 34 || b === 92)
                  break;
                j += 1;
              }
              if (j - i >= 16) {
                this.bufferedString.appendBuf(buffer, i, j);
              } else {
                for (let k = i;k < j; k += 1)
                  this.bufferedString.appendChar(buffer[k]);
              }
              i = j - 1;
              continue;
            }
            break;
          case 19: {
            const available = Math.min(this.bytes_remaining, buffer.length - i);
            this.char_split_buffer.set(buffer.subarray(i, i + available), this.bytes_in_sequence - this.bytes_remaining);
            this.bytes_remaining -= available;
            if (this.bytes_remaining > 0) {
              i = buffer.length - 1;
              continue;
            }
            this.bufferedString.appendBuf(this.char_split_buffer, 0, this.bytes_in_sequence);
            i += available - 1;
            this.state = 13;
            continue;
          }
          case 14: {
            const controlChar = escapedSequences[n];
            if (controlChar) {
              this.flushPendingHighSurrogate();
              this.bufferedString.appendChar(controlChar);
              this.escapedCharsByteLength += 1;
              this.state = 13;
              continue;
            }
            if (n === 117) {
              this.unicode = "";
              this.state = 15;
              continue;
            }
            break;
          }
          case 15:
          case 16:
          case 17:
            if (n >= 48 && n <= 57 || n >= 65 && n <= 70 || n >= 97 && n <= 102) {
              this.unicode += String.fromCharCode(n);
              this.state += 1;
              continue;
            }
            break;
          case 18:
            if (n >= 48 && n <= 57 || n >= 65 && n <= 70 || n >= 97 && n <= 102) {
              const intVal = parseInt(this.unicode + String.fromCharCode(n), 16);
              this.appendUnicodeCodeUnit(intVal);
              this.state = 13;
              continue;
            }
            break;
          case 20:
            if (n === 48) {
              this.bufferedNumber.appendChar(n);
              this.state = 21;
              continue;
            }
            if (n >= 49 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              this.state = 22;
              continue;
            }
            break;
          case 21:
            if (n === 46) {
              this.bufferedNumber.appendChar(n);
              this.state = 23;
              continue;
            }
            if (n === 101 || n === 69) {
              this.bufferedNumber.appendChar(n);
              this.state = 25;
              continue;
            }
            i -= 1;
            this.state = 0;
            this.emitNumber();
            continue;
          case 22:
            if (n >= 48 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              continue;
            }
            if (n === 46) {
              this.bufferedNumber.appendChar(n);
              this.state = 23;
              continue;
            }
            if (n === 101 || n === 69) {
              this.bufferedNumber.appendChar(n);
              this.state = 25;
              continue;
            }
            i -= 1;
            this.state = 0;
            this.emitNumber();
            continue;
          case 23:
            if (n >= 48 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              this.state = 24;
              continue;
            }
            break;
          case 24:
            if (n >= 48 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              continue;
            }
            if (n === 101 || n === 69) {
              this.bufferedNumber.appendChar(n);
              this.state = 25;
              continue;
            }
            i -= 1;
            this.state = 0;
            this.emitNumber();
            continue;
          case 25:
            if (n === 43 || n === 45) {
              this.bufferedNumber.appendChar(n);
              this.state = 26;
              continue;
            }
          case 26:
            if (n >= 48 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              this.state = 27;
              continue;
            }
            break;
          case 27:
            if (n >= 48 && n <= 57) {
              this.bufferedNumber.appendChar(n);
              continue;
            }
            i -= 1;
            this.state = 0;
            this.emitNumber();
            continue;
          case 3:
            if (n === 114) {
              this.state = 4;
              continue;
            }
            break;
          case 4:
            if (n === 117) {
              this.state = 5;
              continue;
            }
            break;
          case 5:
            if (n === 101) {
              this.state = 0;
              this.onToken({
                token: tokenType_default.TRUE,
                value: true,
                offset: this.offset
              });
              this.offset += 3;
              continue;
            }
            break;
          case 6:
            if (n === 97) {
              this.state = 7;
              continue;
            }
            break;
          case 7:
            if (n === 108) {
              this.state = 8;
              continue;
            }
            break;
          case 8:
            if (n === 115) {
              this.state = 9;
              continue;
            }
            break;
          case 9:
            if (n === 101) {
              this.state = 0;
              this.onToken({
                token: tokenType_default.FALSE,
                value: false,
                offset: this.offset
              });
              this.offset += 4;
              continue;
            }
            break;
          case 10:
            if (n === 117) {
              this.state = 11;
              continue;
            }
            break;
          case 11:
            if (n === 108) {
              this.state = 12;
              continue;
            }
            break;
          case 12:
            if (n === 108) {
              this.state = 0;
              this.onToken({
                token: tokenType_default.NULL,
                value: null,
                offset: this.offset
              });
              this.offset += 3;
              continue;
            }
            break;
          case 28:
            this.separatorIndex += 1;
            if (!this.separatorBytes || n !== this.separatorBytes[this.separatorIndex]) {
              break;
            }
            if (this.separatorIndex === this.separatorBytes.length - 1) {
              this.state = 0;
              this.onToken({
                token: tokenType_default.SEPARATOR,
                value: this.separator,
                offset: this.offset + this.separatorIndex
              });
              this.separatorIndex = 0;
            }
            continue;
          case 30:
            if (n === this.bom[this.bomIndex]) {
              if (this.bomIndex === this.bom.length - 1) {
                this.state = 0;
                this.bom = undefined;
                this.bomIndex = 0;
                continue;
              }
              this.bomIndex += 1;
              continue;
            }
            break;
          case 1:
            if (n === 32 || n === 10 || n === 13 || n === 9) {
              continue;
            }
        }
        throw new TokenizerError(`Unexpected "${String.fromCharCode(n)}" at chunk position "${i}" (absolute position "${this.streamByteLength + i}") in state ${TokenizerStateToString(this.state)}`);
      }
      this.streamByteLength += buffer.length;
      if (this.emitPartialTokens) {
        switch (this.state) {
          case 3:
          case 4:
          case 5:
            this.onToken({
              token: tokenType_default.TRUE,
              value: true,
              offset: this.offset,
              partial: true
            });
            break;
          case 6:
          case 7:
          case 8:
          case 9:
            this.onToken({
              token: tokenType_default.FALSE,
              value: false,
              offset: this.offset,
              partial: true
            });
            break;
          case 10:
          case 11:
          case 12:
            this.onToken({
              token: tokenType_default.NULL,
              value: null,
              offset: this.offset,
              partial: true
            });
            break;
          case 13: {
            const string = this.bufferedString.toString();
            this.onToken({
              token: tokenType_default.STRING,
              value: string,
              offset: this.offset,
              partial: true
            });
            break;
          }
          case 21:
          case 22:
          case 24:
          case 27:
            try {
              this.onToken({
                token: tokenType_default.NUMBER,
                value: this.parseNumber(this.bufferedNumber.toString()),
                offset: this.offset,
                partial: true
              });
            } catch (_a) {}
        }
      }
    } catch (err) {
      this.error(err);
    }
  }
  emitNumber() {
    this.onToken({
      token: tokenType_default.NUMBER,
      value: this.parseNumber(this.bufferedNumber.toString()),
      offset: this.offset
    });
    this.offset += this.bufferedNumber.byteLength - 1;
  }
  parseNumber(numberStr) {
    return Number(numberStr);
  }
  error(err) {
    if (this.state !== 1) {
      this.state = 2;
    }
    this.onError(err);
  }
  end() {
    switch (this.state) {
      case 21:
      case 22:
      case 24:
      case 27:
        this.state = 1;
        this.emitNumber();
        this.onEnd();
        break;
      case 29:
      case 0:
      case 2:
        this.state = 1;
        this.onEnd();
        break;
      default:
        this.error(new TokenizerError(`Tokenizer ended in the middle of a token (state: ${TokenizerStateToString(this.state)}). Either not all the data was received or the data was invalid.`));
    }
  }
  onToken(parsedToken) {
    throw new TokenizerError(`Can't emit tokens before the "onToken" callback has been set up.`);
  }
  onError(err) {
    throw err;
  }
  onEnd() {}
}

// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/tokenparser.js
var TokenParserState;
(function(TokenParserState2) {
  TokenParserState2[TokenParserState2["VALUE"] = 0] = "VALUE";
  TokenParserState2[TokenParserState2["KEY"] = 1] = "KEY";
  TokenParserState2[TokenParserState2["COLON"] = 2] = "COLON";
  TokenParserState2[TokenParserState2["COMMA"] = 3] = "COMMA";
  TokenParserState2[TokenParserState2["ENDED"] = 4] = "ENDED";
  TokenParserState2[TokenParserState2["ERROR"] = 5] = "ERROR";
  TokenParserState2[TokenParserState2["SEPARATOR"] = 6] = "SEPARATOR";
})(TokenParserState || (TokenParserState = {}));
function TokenParserStateToString(state) {
  return ["VALUE", "KEY", "COLON", "COMMA", "ENDED", "ERROR", "SEPARATOR"][state];
}
function setProperty(obj, key, value) {
  if (key === "__proto__") {
    Object.defineProperty(obj, key, {
      value,
      writable: true,
      enumerable: true,
      configurable: true
    });
    return;
  }
  obj[key] = value;
}
var defaultOpts2 = {
  paths: undefined,
  keepStack: true,
  separator: undefined,
  emitPartialValues: false
};

class TokenParserError extends Error {
  constructor(message) {
    super(message);
    Object.setPrototypeOf(this, TokenParserError.prototype);
  }
}

class TokenParser {
  constructor(opts) {
    this.state = 0;
    this.mode = undefined;
    this.key = undefined;
    this.value = undefined;
    this.stack = [];
    this.memberCount = 0;
    opts = Object.assign(Object.assign({}, defaultOpts2), opts);
    if (opts.paths) {
      const root = { children: new Map, terminal: false };
      let matchEverything = false;
      for (const path of opts.paths) {
        if (path === undefined || path === "$*") {
          matchEverything = true;
          continue;
        }
        if (!path.startsWith("$"))
          throw new TokenParserError(`Invalid selector "${path}". Should start with "$".`);
        const segments = path.split(".").slice(1);
        if (segments.includes(""))
          throw new TokenParserError(`Invalid selector "${path}". ".." syntax not supported.`);
        let node = root;
        for (const segment of segments) {
          let child = node.children.get(segment);
          if (!child) {
            child = { children: new Map, terminal: false };
            node.children.set(segment, child);
          }
          node = child;
        }
        node.terminal = true;
      }
      if (!matchEverything)
        this.selectorTrie = root;
    }
    this.keepStack = opts.keepStack || false;
    this.separator = opts.separator;
    if (!opts.emitPartialValues) {
      this.emitPartial = () => {};
    }
  }
  shouldEmit() {
    if (!this.selectorTrie)
      return true;
    return this.matchesSelector(this.selectorTrie, 0);
  }
  matchesSelector(node, level) {
    const keyCount = this.stack.length;
    if (level === keyCount)
      return node.terminal;
    const key = level < keyCount - 1 ? this.stack[level + 1].key : this.key;
    const wildcard = node.children.get("*");
    if (wildcard && this.matchesSelector(wildcard, level + 1))
      return true;
    const hasLiteralChild = node.children.size > (wildcard ? 1 : 0);
    if (hasLiteralChild) {
      const segment = key === null || key === undefined ? undefined : key.toString();
      if (segment !== undefined) {
        const child = node.children.get(segment);
        if (child && this.matchesSelector(child, level + 1))
          return true;
      }
    }
    return false;
  }
  push() {
    this.stack.push({
      key: this.key,
      value: this.value,
      mode: this.mode,
      emit: this.shouldEmit(),
      memberCount: this.memberCount
    });
  }
  pop() {
    const value = this.value;
    let emit;
    ({
      key: this.key,
      value: this.value,
      mode: this.mode,
      emit,
      memberCount: this.memberCount
    } = this.stack.pop());
    this.state = this.mode !== undefined ? 3 : 0;
    this.emit(value, emit);
  }
  emit(value, emit) {
    if (!this.keepStack && this.value && this.stack.every((item) => !item.emit)) {
      if (Array.isArray(this.value)) {
        this.value.length -= 1;
      } else {
        delete this.value[this.key];
      }
    }
    if (emit) {
      this.onValue({
        value,
        key: this.key,
        parent: this.value,
        stack: this.stack
      });
    }
    if (this.stack.length === 0) {
      if (this.separator) {
        this.state = 6;
      } else if (this.separator === undefined) {
        this.end();
      }
    }
  }
  emitPartial(value) {
    if (!this.shouldEmit())
      return;
    if (this.state === 1) {
      this.onValue({
        value: undefined,
        key: value,
        parent: this.value,
        stack: this.stack,
        partial: true
      });
      return;
    }
    this.onValue({
      value,
      key: this.key,
      parent: this.value,
      stack: this.stack,
      partial: true
    });
  }
  get isEnded() {
    return this.state === 4;
  }
  write({ token, value, partial }) {
    try {
      if (partial) {
        if (this.state !== 0 && this.state !== 1) {
          throw new TokenParserError(`Unexpected partial ${tokenType_default[token]} (${JSON.stringify(value)}) in state ${TokenParserStateToString(this.state)}`);
        }
        this.emitPartial(value);
        return;
      }
      if (this.state === 0) {
        if (token === tokenType_default.STRING || token === tokenType_default.NUMBER || token === tokenType_default.TRUE || token === tokenType_default.FALSE || token === tokenType_default.NULL) {
          if (this.mode === 0) {
            setProperty(this.value, this.key, value);
            this.state = 3;
            this.memberCount++;
          } else if (this.mode === 1) {
            this.value.push(value);
            this.state = 3;
            this.memberCount++;
          }
          this.emit(value, this.shouldEmit());
          return;
        }
        if (token === tokenType_default.LEFT_BRACE) {
          this.memberCount++;
          this.push();
          if (this.mode === 0) {
            const val = {};
            setProperty(this.value, this.key, val);
            this.value = val;
          } else if (this.mode === 1) {
            const val = {};
            this.value.push(val);
            this.value = val;
          } else {
            this.value = {};
          }
          this.mode = 0;
          this.state = 1;
          this.key = undefined;
          this.memberCount = 0;
          this.emitPartial();
          return;
        }
        if (token === tokenType_default.LEFT_BRACKET) {
          this.memberCount++;
          this.push();
          if (this.mode === 0) {
            const val = [];
            setProperty(this.value, this.key, val);
            this.value = val;
          } else if (this.mode === 1) {
            const val = [];
            this.value.push(val);
            this.value = val;
          } else {
            this.value = [];
          }
          this.mode = 1;
          this.state = 0;
          this.key = 0;
          this.memberCount = 0;
          this.emitPartial();
          return;
        }
        if (this.mode === 1 && token === tokenType_default.RIGHT_BRACKET && this.memberCount === 0) {
          this.pop();
          return;
        }
      }
      if (this.state === 1) {
        if (token === tokenType_default.STRING) {
          this.key = value;
          this.state = 2;
          this.emitPartial();
          return;
        }
        if (token === tokenType_default.RIGHT_BRACE && this.memberCount === 0) {
          this.pop();
          return;
        }
      }
      if (this.state === 2) {
        if (token === tokenType_default.COLON) {
          this.state = 0;
          return;
        }
      }
      if (this.state === 3) {
        if (token === tokenType_default.COMMA) {
          if (this.mode === 1) {
            this.state = 0;
            this.key += 1;
            return;
          }
          if (this.mode === 0) {
            this.state = 1;
            return;
          }
        }
        if (token === tokenType_default.RIGHT_BRACE && this.mode === 0 || token === tokenType_default.RIGHT_BRACKET && this.mode === 1) {
          this.pop();
          return;
        }
      }
      if (this.state === 6) {
        if (token === tokenType_default.SEPARATOR && value === this.separator) {
          this.state = 0;
          return;
        }
      }
      if (token === tokenType_default.SEPARATOR && this.state !== 6 && Array.from(value).map((n) => n.charCodeAt(0)).every((n) => n === 32 || n === 10 || n === 13 || n === 9)) {
        return;
      }
      throw new TokenParserError(`Unexpected ${tokenType_default[token]} (${JSON.stringify(value)}) in state ${TokenParserStateToString(this.state)}`);
    } catch (err) {
      this.error(err);
    }
  }
  error(err) {
    if (this.state !== 4) {
      this.state = 5;
    }
    this.onError(err);
  }
  end() {
    if (this.state !== 0 && this.state !== 6 || this.stack.length > 0) {
      this.error(new Error(`Parser ended in mid-parsing (state: ${TokenParserStateToString(this.state)}). Either not all the data was received or the data was invalid.`));
    } else {
      this.state = 4;
      this.onEnd();
    }
  }
  onValue(parsedElementInfo) {
    throw new TokenParserError(`Can't emit data before the "onValue" callback has been set up.`);
  }
  onError(err) {
    throw err;
  }
  onEnd() {}
}

// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/jsonparser.js
class JSONParser {
  constructor(opts = {}) {
    this.tokenizer = new Tokenizer(opts);
    this.tokenParser = new TokenParser(opts);
    this.tokenizer.onToken = this.tokenParser.write.bind(this.tokenParser);
    this.tokenizer.onEnd = () => {
      if (!this.tokenParser.isEnded)
        this.tokenParser.end();
    };
    this.tokenParser.onError = this.tokenizer.error.bind(this.tokenizer);
    this.tokenParser.onEnd = () => {
      if (!this.tokenizer.isEnded)
        this.tokenizer.end();
    };
  }
  get isEnded() {
    return this.tokenizer.isEnded && this.tokenParser.isEnded;
  }
  write(input) {
    this.tokenizer.write(input);
  }
  end() {
    this.tokenizer.end();
  }
  set onToken(cb) {
    this.tokenizer.onToken = (parsedToken) => {
      cb(parsedToken);
      this.tokenParser.write(parsedToken);
    };
  }
  set onValue(cb) {
    this.tokenParser.onValue = cb;
  }
  set onError(cb) {
    this.tokenizer.onError = cb;
  }
  set onEnd(cb) {
    this.tokenParser.onEnd = () => {
      if (!this.tokenizer.isEnded)
        this.tokenizer.end();
      cb.call(this.tokenParser);
    };
  }
}
// node_modules/.bun/@streamparser+json@0.0.26/node_modules/@streamparser/json/dist/mjs/utils/types/stackElement.js
var TokenParserMode;
(function(TokenParserMode2) {
  TokenParserMode2[TokenParserMode2["OBJECT"] = 0] = "OBJECT";
  TokenParserMode2[TokenParserMode2["ARRAY"] = 1] = "ARRAY";
})(TokenParserMode || (TokenParserMode = {}));
// packages/safehar-core/src/stream-parser.ts
class HarStreamParser {
  parser;
  entryIndex = 0;
  totalRedacted = 0;
  summaries = [];
  batch = [];
  sanitizedEntries = [];
  batchSize;
  redactionOptions;
  onBatch;
  onProgress;
  onEntrySanitized;
  metadata = { version: "1.2" };
  constructor(options = {}) {
    this.batchSize = options.batchSize || 50;
    this.redactionOptions = options.redactionOptions || DEFAULT_REDACTION_OPTIONS;
    this.onBatch = options.onBatch;
    this.onProgress = options.onProgress;
    this.onEntrySanitized = options.onEntrySanitized;
    this.parser = new JSONParser({
      paths: ["$.log.entries.*", "$.log.version", "$.log.creator", "$.log.browser", "$.log.pages"],
      keepStack: false
    });
    this.parser.onValue = ({ value, key, stack }) => {
      if (stack && stack.length > 0) {
        const parentKey = stack[stack.length - 1]?.key;
        if (parentKey === "log") {
          if (key === "version" && typeof value === "string")
            this.metadata.version = value;
          if (key === "creator" && typeof value === "object" && value !== null)
            this.metadata.creator = value;
          if (key === "browser" && typeof value === "object" && value !== null)
            this.metadata.browser = value;
          if (key === "pages" && Array.isArray(value))
            this.metadata.pages = value;
          return;
        }
      }
      const entryObj = value;
      if (entryObj && typeof entryObj === "object" && (entryObj.request || entryObj.response)) {
        this.processEntry(entryObj);
      }
    };
  }
  processEntry(rawEntry) {
    const { sanitizedEntry, summary } = sanitizeEntry(rawEntry, this.entryIndex, this.redactionOptions);
    this.entryIndex++;
    this.totalRedacted += summary.redactedFieldsCount;
    this.summaries.push(summary);
    this.batch.push(summary);
    if (this.onEntrySanitized) {
      this.onEntrySanitized(sanitizedEntry, this.entryIndex - 1);
    } else {
      this.sanitizedEntries.push(sanitizedEntry);
    }
    if (this.batch.length >= this.batchSize) {
      if (this.onBatch) {
        this.onBatch([...this.batch]);
      }
      if (this.onProgress) {
        this.onProgress({
          type: "PROGRESS",
          count: this.entryIndex
        });
      }
      this.batch = [];
    }
  }
  writeChunk(chunk) {
    this.parser.write(chunk);
  }
  end() {
    if (this.batch.length > 0) {
      if (this.onBatch) {
        this.onBatch([...this.batch]);
      }
      this.batch = [];
    }
    if (this.onProgress) {
      this.onProgress({
        type: "COMPLETE",
        count: this.entryIndex,
        total: this.entryIndex
      });
    }
    return {
      totalEntries: this.entryIndex,
      totalRedactedFields: this.totalRedacted,
      summaries: this.summaries,
      sanitizedEntries: this.sanitizedEntries
    };
  }
  getMetadata() {
    return this.metadata;
  }
}
// packages/safehar-core/src/worker.ts
var currentParser = null;
var collectedSanitizedEntries = [];
if (typeof self !== "undefined" && typeof self.postMessage === "function") {
  self.onmessage = (event) => {
    const msg = event.data;
    try {
      if (msg.type === "START") {
        collectedSanitizedEntries = [];
        currentParser = new HarStreamParser({
          redactionOptions: msg.options,
          batchSize: msg.batchSize || 50,
          onBatch: (summaries) => {
            self.postMessage({ type: "BATCH", summaries });
          },
          onProgress: (progress) => {
            self.postMessage({ type: "PROGRESS", count: progress.count || 0 });
          },
          onEntrySanitized: (entry) => {
            collectedSanitizedEntries.push(entry);
          }
        });
      } else if (msg.type === "CHUNK") {
        if (!currentParser) {
          throw new Error("Parser not initialized. Send START message first.");
        }
        currentParser.writeChunk(msg.chunk);
      } else if (msg.type === "END") {
        if (!currentParser) {
          throw new Error("Parser not initialized.");
        }
        const result = currentParser.end();
        const metadata = currentParser.getMetadata();
        const chunks = [];
        for (const chunk of generateSanitizedHarChunks(metadata, collectedSanitizedEntries)) {
          chunks.push(chunk);
        }
        self.postMessage({
          type: "COMPLETE",
          totalEntries: result.totalEntries,
          totalRedactedFields: result.totalRedactedFields,
          metadata,
          sanitizedHarChunks: chunks
        });
        collectedSanitizedEntries = [];
        currentParser = null;
      }
    } catch (err) {
      self.postMessage({
        type: "ERROR",
        error: err?.message || String(err)
      });
    }
  };
}
// apps/safehar-extension/src/popup.ts
var STORAGE_KEY = "safehar_user_redaction_options";
var fileInput = document.getElementById("file-input");
var dropZone = document.getElementById("drop-zone");
var statusEl = document.getElementById("status");
var statsEl = document.getElementById("stats");
var entriesCountEl = document.getElementById("entries-count");
var redactedCountEl = document.getElementById("redacted-count");
var downloadBtn = document.getElementById("download-btn");
var toggleAuth = document.getElementById("toggle-auth");
var toggleCookies = document.getElementById("toggle-cookies");
var toggleStripe = document.getElementById("toggle-stripe");
var toggleAws = document.getElementById("toggle-aws");
var toggleEmails = document.getElementById("toggle-emails");
var toggleCards = document.getElementById("toggle-cards");
var collectedSanitizedEntries2 = [];
var parsedMetadata = {};
var targetFileName = "sanitized-export.har";
async function loadPreferences() {
  return new Promise((resolve) => {
    if (globalThis.chrome?.storage?.local) {
      chrome.storage.local.get([STORAGE_KEY], (result) => {
        if (result?.[STORAGE_KEY]) {
          resolve(result[STORAGE_KEY]);
        } else {
          resolve(DEFAULT_REDACTION_OPTIONS);
        }
      });
    } else {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        try {
          resolve(JSON.parse(stored));
        } catch {
          resolve(DEFAULT_REDACTION_OPTIONS);
        }
      } else {
        resolve(DEFAULT_REDACTION_OPTIONS);
      }
    }
  });
}
function savePreferences(options) {
  if (globalThis.chrome?.storage?.local) {
    chrome.storage.local.set({ [STORAGE_KEY]: options });
  } else {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(options));
  }
}
function getActiveOptions() {
  return {
    maskAuthHeaders: toggleAuth ? toggleAuth.checked : true,
    maskCookies: toggleCookies ? toggleCookies.checked : true,
    maskStripeKeys: toggleStripe ? toggleStripe.checked : true,
    maskAwsKeys: toggleAws ? toggleAws.checked : true,
    maskEmails: toggleEmails ? toggleEmails.checked : true,
    maskCreditCards: toggleCards ? toggleCards.checked : true
  };
}
function syncCheckboxes(options) {
  if (toggleAuth)
    toggleAuth.checked = options.maskAuthHeaders;
  if (toggleCookies)
    toggleCookies.checked = options.maskCookies;
  if (toggleStripe)
    toggleStripe.checked = options.maskStripeKeys;
  if (toggleAws)
    toggleAws.checked = options.maskAwsKeys;
  if (toggleEmails)
    toggleEmails.checked = options.maskEmails;
  if (toggleCards)
    toggleCards.checked = options.maskCreditCards;
}
[toggleAuth, toggleCookies, toggleStripe, toggleAws, toggleEmails, toggleCards].forEach((el) => {
  el?.addEventListener("change", () => {
    savePreferences(getActiveOptions());
  });
});
async function processFile(file) {
  targetFileName = `${file.name.replace(/\.har$/i, "")}-sanitized.har`;
  collectedSanitizedEntries2 = [];
  downloadBtn.classList.add("hidden");
  statsEl.classList.add("hidden");
  statusEl.classList.remove("hidden");
  statusEl.innerText = "Memproses berkas HAR streaming di sisi klien...";
  const parser = new HarStreamParser({
    redactionOptions: getActiveOptions(),
    batchSize: 50,
    onEntrySanitized: (entry) => {
      collectedSanitizedEntries2.push(entry);
    }
  });
  const stream = file.stream();
  const reader = stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done)
        break;
      if (value) {
        parser.writeChunk(value);
      }
    }
    const res = parser.end();
    parsedMetadata = parser.getMetadata();
    statusEl.classList.add("hidden");
    statsEl.classList.remove("hidden");
    entriesCountEl.innerText = String(res.totalEntries);
    redactedCountEl.innerText = String(res.totalRedactedFields);
    downloadBtn.classList.remove("hidden");
  } catch (err) {
    statusEl.innerText = `Galat sanitasi: ${err?.message || err}`;
  } finally {
    reader.releaseLock();
  }
}
fileInput?.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file)
    processFile(file);
});
dropZone?.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("border-emerald-400");
});
dropZone?.addEventListener("dragleave", () => {
  dropZone.classList.remove("border-emerald-400");
});
dropZone?.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("border-emerald-400");
  const file = e.dataTransfer?.files?.[0];
  if (file)
    processFile(file);
});
downloadBtn?.addEventListener("click", () => {
  const chunks = [];
  for (const chunk of generateSanitizedHarChunks(parsedMetadata, collectedSanitizedEntries2)) {
    chunks.push(chunk);
  }
  const blob = new Blob(chunks, { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = targetFileName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});
document.addEventListener("DOMContentLoaded", async () => {
  const options = await loadPreferences();
  syncCheckboxes(options);
});
