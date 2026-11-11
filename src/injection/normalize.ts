/**
 * Text canonicalisation for the injection detector.
 *
 * Must stay identical to `normalize` in ml/features.py: the model was trained
 * on text normalised this way, and tests/fixtures/injection-golden.json checks
 * the two implementations against each other.
 */

const TAG_LETTERS = /[\u{E0020}-\u{E007E}]/gu;
const INVISIBLE = /[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF\u{E0000}-\u{E007F}]/gu;
const ASCII_UPPER = /[A-Z]/g;
const SPACE_RUN = /[ \t\n\r\f\v\u00A0\u2028\u2029]+/g;
const EDGE_SPACES = /^ +| +$/g;

export function normalize(text: string): string {
  return (
    text
      .normalize("NFKC")
      // Unicode "tag" characters are invisible copies of ASCII; make them visible.
      .replace(TAG_LETTERS, (c) => String.fromCharCode((c.codePointAt(0) as number) - 0xe0000))
      .replace(INVISIBLE, "")
      // ASCII only: full Unicode lower-casing differs between runtimes.
      .replace(ASCII_UPPER, (c) => String.fromCharCode(c.charCodeAt(0) + 32))
      .replace(SPACE_RUN, " ")
      .replace(EDGE_SPACES, "")
  );
}
