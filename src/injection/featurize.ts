/**
 * Feature hashing for the injection detector. Mirrors ml/features.py; every
 * constant here is part of the model format.
 */

export const N_FEATURES = 1 << 18;
export const WINDOW = 512;
export const STRIDE = 256;

const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;
const UNIGRAM_PREFIX = 0x11;
const BIGRAM_PREFIX = 0x12;
const MASK = N_FEATURES - 1;

/** Overlapping [start, end) byte ranges covering a text of `nBytes`. */
export function windows(nBytes: number): [number, number][] {
  if (nBytes <= 0) return [];
  if (nBytes <= WINDOW) return [[0, nBytes]];
  const out: [number, number][] = [];
  for (let s = 0; s + WINDOW <= nBytes; s += STRIDE) out.push([s, s + WINDOW]);
  if (out[out.length - 1][1] < nBytes) out.push([nBytes - WINDOW, nBytes]);
  return out;
}

function isTokenByte(b: number): boolean {
  return (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) || b >= 0x80;
}

/**
 * Call `emit` with the feature index of every n-gram in bytes[start, end).
 * Indices repeat; callers de-duplicate. Runs in O(end - start).
 */
export function forEachFeature(bytes: Uint8Array, start: number, end: number, emit: (index: number) => void): void {
  // Byte 3-, 4- and 5-grams, each hashed with its length as a prefix byte.
  for (let i = start; i + 3 <= end; i++) {
    for (let n = 3; n <= 5 && i + n <= end; n++) {
      let h = Math.imul(FNV_OFFSET ^ n, FNV_PRIME);
      for (let j = 0; j < n; j++) h = Math.imul(h ^ bytes[i + j], FNV_PRIME);
      emit((h >>> 0) & MASK);
    }
  }
  // Word unigrams and bigrams. The bigram hash continues from the previous
  // token's bytes, so each token is read at most twice.
  let prevStart = -1;
  let prevEnd = -1;
  let i = start;
  while (i < end) {
    if (!isTokenByte(bytes[i])) {
      i++;
      continue;
    }
    const tokenStart = i;
    let h = Math.imul(FNV_OFFSET ^ UNIGRAM_PREFIX, FNV_PRIME);
    while (i < end && isTokenByte(bytes[i])) h = Math.imul(h ^ bytes[i++], FNV_PRIME);
    emit((h >>> 0) & MASK);
    if (prevStart >= 0) {
      let g = Math.imul(FNV_OFFSET ^ BIGRAM_PREFIX, FNV_PRIME);
      for (let j = prevStart; j < prevEnd; j++) g = Math.imul(g ^ bytes[j], FNV_PRIME);
      g = Math.imul(g ^ 0x20, FNV_PRIME);
      for (let j = tokenStart; j < i; j++) g = Math.imul(g ^ bytes[j], FNV_PRIME);
      emit((g >>> 0) & MASK);
    }
    prevStart = tokenStart;
    prevEnd = i;
  }
}

/** Sorted distinct feature indices of one window. */
export function featurize(window: Uint8Array): Uint32Array {
  const seen = new Set<number>();
  forEachFeature(window, 0, window.length, (i) => seen.add(i));
  return Uint32Array.from(seen).sort();
}
