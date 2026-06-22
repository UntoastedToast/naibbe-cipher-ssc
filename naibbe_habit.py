# Habit extension of the Naibbe cipher: when a plaintext token recurs
# within a short visibility window, the previously-written glyph is
# copied instead of drawing a fresh substitution table card.

from __future__ import annotations

import argparse
import collections
import os
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
_PREV_CWD = os.getcwd()
try:
    os.chdir(_REPO_ROOT)
    import naibbe_v2
finally:
    os.chdir(_PREV_CWD)


# === Re-exports for callers that want a single import surface ===
ALPHABET = naibbe_v2.ALPHABET
TABLES = naibbe_v2.TABLES
CARD_WEIGHTS = naibbe_v2.CARD_WEIGHTS
naibbe_tables = naibbe_v2.naibbe_tables
placeholder_to_glyph = naibbe_v2.placeholder_to_glyph
unigram_glyphs = naibbe_v2.unigram_glyphs
bigram_catalog = naibbe_v2.bigram_catalog
create_card_deck = naibbe_v2.create_card_deck
respace_plaintext = naibbe_v2.respace_plaintext
clean_line = naibbe_v2.clean_line
respace_line = naibbe_v2.respace_line
UNAMBIGUOUS = naibbe_v2.UNAMBIGUOUS
MAX_BIGRAM_RETRIES = naibbe_v2.MAX_BIGRAM_RETRIES
USE_78_CARD_DECK = naibbe_v2.USE_78_CARD_DECK
SPACE_REMOVAL_RATE = naibbe_v2.SPACE_REMOVAL_RATE
RESPACING = naibbe_v2.RESPACING
encrypt_naibbe = naibbe_v2.encrypt_naibbe


# === Plaintext signature ===
def _plain_sig(token: str) -> tuple:
    """Build a canonical signature for a plaintext token.

    Unigrams become ``('u', char)``; bigrams become ``('b', c1, c2)``.
    Used as the buffer key in :class:`ScribalHabit` and on the
    reuse hot path.
    """
    if len(token) == 1:
        return ("u", token)
    return ("b", token[0], token[1])


# === ScribalHabit: bounded FIFO buffer ===
class ScribalHabit:
    """Bounded FIFO buffer of recent ``(sig, glyph)`` pairs.

    Stores entries in a :class:`collections.deque` with a fixed
    ``maxlen``; the oldest entry is evicted automatically when the
    buffer is full. Lookup scans in reverse insertion order
    (most-recent first).

    Parameters
    ----------
    buffer_size : int
        Maximum number of entries the buffer can hold. Must be >= 1.
    """

    def __init__(self, buffer_size: int) -> None:
        if buffer_size < 1:
            raise ValueError(
                f"ScribalHabit.buffer_size must be >= 1, got {buffer_size}"
            )
        self.buffer_size: int = buffer_size
        self.buffer: collections.deque = collections.deque(maxlen=buffer_size)

    def lookup(self, sig: tuple) -> tuple[tuple, str] | None:
        """Return the most-recent entry whose ``sig`` matches, else ``None``.

        Scans in reverse insertion order (most-recent first).
        Returns the ``(sig, glyph)`` tuple; callers only need the glyph.
        """
        for entry in reversed(self.buffer):
            if entry[0] == sig:
                return entry
        return None

    def push(self, sig: tuple, glyph: str) -> None:
        """Append a new ``(sig, glyph)`` entry to the buffer.

        If the buffer is full, the oldest entry is automatically
        evicted by the underlying ``deque(maxlen=...)``.
        """
        self.buffer.append((sig, glyph))

    def __len__(self) -> int:
        return len(self.buffer)


# === Deck-draw helper ===================================================
def _next_table(
    deck: list[str], deck_index: int, use_78: bool
) -> tuple[str, list[str], int]:
    """Draw the next table from ``deck``, refilling it if exhausted.

    Returns ``(table, deck, deck_index)`` so callers can rebind the
    mutable deck/index state in one line. Mirrors the inline
    ``if deck_index >= len(deck): deck = create_card_deck(...)``
    block used throughout :func:`naibbe_v2.encrypt_naibbe`; factoring
    it out keeps the Habit draw paths DRY against the 5 sites that
    previously inlined it.
    """
    if deck_index >= len(deck):
        deck = create_card_deck(use_78)
        deck_index = 0
    table = deck[deck_index]
    deck_index += 1
    return table, deck, deck_index


# === Encryption with optional ScribalHabit buffer ===
def encrypt_naibbe_habit(
    plaintext: str,
    tables: dict,
    glyph_map: dict,
    use_78: bool = False,
    pre_plaintext_file=None,
    habit: ScribalHabit | None = None,
    p_reuse: float = 0.0,
) -> list[str]:
    """Encrypt ``plaintext`` with optional ScribalHabit reuse buffer.

    Each plaintext token is hashed into a signature. If the signature
    is found in ``habit`` and the random check ``random() < p_reuse``
    passes, the cached glyph is re-emitted without advancing the deck.
    Otherwise (miss or non-reuse roll), a fresh card draw is performed
    and the result is pushed into the buffer.

    Parameters
    ----------
    plaintext : str
        Pre-normalized plaintext (call :func:`clean_line` upstream).
    tables : dict
        Substitution tables, see :data:`naibbe_v2.naibbe_tables`.
    glyph_map : dict
        Placeholder → glyph mapping, see :data:`naibbe_v2.placeholder_to_glyph`.
    use_78 : bool
        Use the 78-card deck (vs. 52-card).
    pre_plaintext_file : file-like, optional
        If given, the respaced plaintext is written to it.
    habit : ScribalHabit, optional
        Reuse buffer consulted for every token. If ``None``, no reuse
        is attempted and behavior matches the baseline draw.
    p_reuse : float
        Probability of reusing a cached glyph on a buffer hit. Must
        lie in ``[0.0, 1.0]``.
    """
    # --- No habit: fall through to baseline draw ----------------------
    if habit is None:
        return naibbe_v2.encrypt_naibbe(
            plaintext, tables, glyph_map, use_78, pre_plaintext_file
        )

    # --- Habit path -----------------------------------------------------
    ngrams = respace_plaintext(plaintext, pre_plaintext_file)
    ciphertext: list[str] = []
    deck = create_card_deck(use_78)
    deck_index = 0

    for token in ngrams:
        sig = _plain_sig(token)

        # --- Reuse hot path --------------------------------------------
        entry = habit.lookup(sig)
        if entry is not None:
            if p_reuse >= 1.0 or (p_reuse > 0.0 and random.random() < p_reuse):
                # Scribe laziness: re-emit the cached glyph verbatim,
                # skip the draw, skip the push.
                ciphertext.append(entry[1])  # entry[1] is glyph
                continue

        # --- Fresh draw ------------------------------------------------
        if len(token) == 1:
            # === Unigram ===
            table, deck, deck_index = _next_table(deck, deck_index, use_78)
            code = tables[table][("unigram", token)]
            glyph = glyph_map.get(code, code)
            ciphertext.append(glyph)
            habit.push(sig, glyph)

        else:
            # === Bigram ===
            a, b = token[0], token[1]
            if UNAMBIGUOUS:
                # === Ambiguity-safe bigram ===
                accepted = False
                # Initialize so the fallback below is type-safe even if the
                # retry loop were skipped (it never is -- MAX_BIGRAM_RETRIES >= 1
                # -- but this satisfies static analysis and is harmless).
                glyph_prefix = ""
                glyph_suffix = ""
                for _ in range(MAX_BIGRAM_RETRIES):
                    # Prefix
                    table_prefix, deck, deck_index = _next_table(
                        deck, deck_index, use_78
                    )
                    code_prefix = tables[table_prefix][("prefix", a)]
                    glyph_prefix = glyph_map.get(code_prefix, code_prefix)

                    # Suffix
                    table_suffix, deck, deck_index = _next_table(
                        deck, deck_index, use_78
                    )
                    code_suffix = tables[table_suffix][("suffix", b)]
                    glyph_suffix = glyph_map.get(code_suffix, code_suffix)

                    combined = glyph_prefix + glyph_suffix

                    # 1) reject if equals any unigram glyph
                    if combined in unigram_glyphs:
                        naibbe_v2.ambiguity_retries += 1
                        continue

                    # 2) reject if any other (prefix, suffix) pair yields same string
                    pairs = bigram_catalog.get(combined, set())
                    if any(pair != (code_prefix, code_suffix) for pair in pairs):
                        naibbe_v2.ambiguity_retries += 1
                        continue

                    # Accepted.
                    ciphertext.append(combined)
                    habit.push(sig, combined)
                    accepted = True
                    break

                if not accepted:
                    # Exhausted retries; emit the last attempt to avoid deadlock
                    # (mirrors naibbe_v2 fallback). Do NOT push to buffer: the
                    # fallback glyph may violate the UNAMBIGUOUS invariant, and
                    # the buffer's contract is "stores validated draws only".
                    ciphertext.append(glyph_prefix + glyph_suffix)
            else:
                # === Standard bigram (no collision checks) ===
                # Prefix
                table_prefix, deck, deck_index = _next_table(
                    deck, deck_index, use_78
                )
                code_prefix = tables[table_prefix][("prefix", a)]
                glyph_prefix = glyph_map.get(code_prefix, code_prefix)

                # Suffix
                table_suffix, deck, deck_index = _next_table(
                    deck, deck_index, use_78
                )
                code_suffix = tables[table_suffix][("suffix", b)]
                glyph_suffix = glyph_map.get(code_suffix, code_suffix)

                combined = glyph_prefix + glyph_suffix
                ciphertext.append(combined)
                habit.push(sig, combined)

    return ciphertext


# === File-level encryption driver (shared by CLI and eval) =============
def iter_encrypted_lines(
    input_path: str,
    use_78: bool,
    habit: ScribalHabit | None,
    p_reuse: float,
    pre_plaintext_file=None,
):
    """Yield ``(cleaned, tokens)`` for each line of ``input_path``.

    For non-blank lines, ``cleaned`` is the :func:`clean_line` output
    and ``tokens`` is the ciphertext token list from
    :func:`encrypt_naibbe_habit`. For blank lines, both are empty
    (``""`` and ``[]``) so callers can preserve the input's line
    structure in their output.
    """
    with open(input_path, "r", encoding="utf-8") as fin:
        for line in fin:
            cleaned = clean_line(line)
            if cleaned:
                tokens = encrypt_naibbe_habit(
                    cleaned,
                    naibbe_tables,
                    placeholder_to_glyph,
                    use_78=use_78,
                    pre_plaintext_file=pre_plaintext_file,
                    habit=habit,
                    p_reuse=p_reuse,
                )
            else:
                tokens = []
            yield cleaned, tokens


# === CLI ===
def build_parser() -> argparse.ArgumentParser:
    """Build the :mod:`argparse` parser for the Habit CLI."""
    p = argparse.ArgumentParser(
        prog="naibbe-habit",
        description=(
            "Naibbe cipher generator with optional ScribalHabit reuse buffer. "
            "When --use-habit is omitted, behavior matches the baseline draw."
        ),
    )
    p.add_argument(
        "--input",
        default="input/examples/nathist_book16.txt",
        help="Path to the input plaintext file.",
    )
    p.add_argument(
        "--output",
        default="encrypted/nathist_output_ciphertext_bigram_unambig.txt",
        help="Path to the ciphertext output file.",
    )
    p.add_argument(
        "--respaced-output",
        default="encrypted/nathist_output_ciphertext_respaced_bigram_unambig.txt",
        help="Path to the respaced ciphertext output (with space-drop).",
    )
    p.add_argument(
        "--pre-plaintext-output",
        default="respaced_plaintext/nathist_pre_encryption_respaced_plaintext_bigram_unambig.txt",
        help="Path to the pre-encryption respaced plaintext output.",
    )
    p.add_argument(
        "--use-78",
        action="store_true",
        default=USE_78_CARD_DECK,
        help="Use the 78-card deck (vs. 52-card).",
    )
    p.add_argument(
        "--use-habit",
        action="store_true",
        default=False,
        help="Enable the ScribalHabit reuse buffer.",
    )
    p.add_argument(
        "--buffer-size",
        type=int,
        default=50,
        help="Maximum number of entries the reuse buffer can hold (>= 1).",
    )
    p.add_argument(
        "--p-reuse",
        type=float,
        default=0.3,
        help="Probability of reusing a cached glyph on a buffer hit "
        "(only effective when --use-habit is set).",
    )
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional integer seed for Python's `random` module.",
    )
    return p


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args via :func:`parse_known_args` for Jupyter safety.

    Unknown args (e.g. Jupyter's ``-f``) are silently ignored.
    """
    parser = build_parser()
    args, _unknown = parser.parse_known_args(argv)
    return args


def main(argv: list[str] | None = None) -> None:
    """Entry point: encrypt an input file with optional ScribalHabit buffer.

    A single ``ScribalHabit`` instance is constructed and threaded
    through every call to :func:`encrypt_naibbe_habit` when
    ``--use-habit`` is set.
    """
    args = parse_args(argv)

    if args.seed is not None:
        random.seed(args.seed)

    if args.use_habit and args.buffer_size < 1:
        # argparse won't catch this for a default of 50; guard explicitly.
        raise ValueError(
            f"--buffer-size must be >= 1 when --use-habit is set, "
            f"got {args.buffer_size}"
        )

    if args.use_habit and not (0.0 <= args.p_reuse <= 1.0):
        raise ValueError(
            f"--p-reuse must lie in [0.0, 1.0] when --use-habit is set, "
            f"got {args.p_reuse}"
        )

    habit = ScribalHabit(args.buffer_size) if args.use_habit else None

    with open(args.output, "w", encoding="utf-8") as fout, \
         open(args.respaced_output, "w", encoding="utf-8") as frespace, \
         open(args.pre_plaintext_output, "w", encoding="utf-8") as fplain:

        for cleaned, encrypted_tokens in iter_encrypted_lines(
            args.input, args.use_78, habit, args.p_reuse, fplain
        ):
            if cleaned:
                line_out = " ".join(encrypted_tokens)
                fout.write(line_out + "\n")
                frespace.write(respace_line(line_out, SPACE_REMOVAL_RATE) + "\n")
            else:
                fout.write("\n")
                frespace.write("\n")
                fplain.write("\n")

    if UNAMBIGUOUS:
        print(f"Total ambiguity retries: {naibbe_v2.ambiguity_retries}")

    if args.use_habit and habit is not None:
        # `habit` is non-None here (constructed above when
        # args.use_habit is True); the `is not None` guard keeps this
        # safe under `python -O` where asserts are stripped.
        print(
            f"Habit stats: buffer_size={habit.buffer_size}, "
            f"p_reuse={args.p_reuse}, "
            f"buffer fill={len(habit)}"
        )


if __name__ == "__main__":
    main(sys.argv[1:])
