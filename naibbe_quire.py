# Quire extension of the Naibbe cipher: the manuscript is processed
# bifolio by bifolio (4 pages per folded sheet). Pages are returned to
# reading order after encryption, so reuse within a bifolio produces
# long-range correlations across pages that are physically far apart
# in the final text.

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


# === Page ↔ Bifolio mapping ================================================

def _page_to_bifolio(page: int, n_bifolia: int) -> tuple[int, int]:
    """Map a reading-order page index to (bifolio_index, page_in_bifolio).

    A quire of n_bifolia has 4*n_bifolia pages. Bifolia are nested:
    the outermost bifolio (k=0) contains the first 2 and last 2 pages;
    the innermost (k=n-1) contains the middle 4 pages.

    For bifolio k:
      - First folio pages: 2k (recto), 2k+1 (verso)
      - Second folio pages: 2*(n-k)-2 (recto), 2*(n-k)-1 (verso)

    Parameters
    ----------
    page : int
        Reading-order page index (0 to 4*n_bifolia - 1).
    n_bifolia : int
        Number of bifolia in the quire.

    Returns
    -------
    (bifolio_index, page_in_bifolio)
        bifolio_index: 0 to n_bifolia-1
        page_in_bifolio: 0, 1, 2, or 3 (0=first folio recto, 1=first folio verso,
                             2=second folio recto, 3=second folio verso)
    """
    half = 2 * n_bifolia  # first half of quire in reading order

    if page < half:
        # First half: pages 0, 1, 2, 3, ..., 2n-1
        bifolio = page // 2
        page_in_bifolio = page % 2  # 0 or 1
    else:
        # Second half: pages 2n, 2n+1, ..., 4n-1 (mirrored)
        offset = page - half
        bifolio = n_bifolia - 1 - offset // 2
        page_in_bifolio = 2 + offset % 2  # 2 or 3

    return bifolio, page_in_bifolio


def _bifolio_to_page(bifolio: int, page_in_bifolio: int, n_bifolia: int) -> int:
    """Map (bifolio_index, page_in_bifolio) back to reading-order page index.

    Inverse of _page_to_bifolio.
    """
    if page_in_bifolio < 2:
        # First folio: pages 2*bifolio, 2*bifolio+1
        return 2 * bifolio + page_in_bifolio
    else:
        # Second folio: pages in the second half, mirrored
        offset = (n_bifolia - 1 - bifolio) * 2 + (page_in_bifolio - 2)
        return 2 * n_bifolia + offset


# === Plaintext signature ===
def _plain_sig(token: str) -> tuple:
    """Build a canonical signature for a plaintext token.

    Unigrams become ``('u', char)``; bigrams become ``('b', c1, c2)``.
    Used as the buffer key in :class:`BifolioMemory` and on the
    reuse hot path.
    """
    if len(token) == 1:
        return ("u", token)
    return ("b", token[0], token[1])


# === BifolioMemory: per-bifolio glyph reuse buffer ===
class BifolioMemory:
    """Bifolio-scoped glyph reuse buffer.

    Stores (sig, glyph) pairs for the current bifolio. When a new
    bifolio starts, the current buffer becomes the "previous bifolio"
    buffer, enabling cross-bifolio reuse with probability
    ``p_cross_bifolio``.
    """

    def __init__(self, p_cross_bifolio: float = 0.1) -> None:
        if not (0.0 <= p_cross_bifolio <= 1.0):
            raise ValueError(
                f"p_cross_bifolio must be in [0.0, 1.0], "
                f"got {p_cross_bifolio}"
            )
        self.p_cross_bifolio = p_cross_bifolio
        self.current_buffer: list[tuple[tuple, str]] = []
        self.previous_buffer: list[tuple[tuple, str]] = []

    def new_bifolio(self) -> None:
        """Archive the current buffer and start a new one."""
        self.previous_buffer = self.current_buffer
        self.current_buffer = []

    def lookup(self, sig: tuple) -> str | None:
        """Look up a sig in the current bifolio, then maybe the previous.

        Returns the glyph if found, else None.
        """
        # First try current bifolio (most-recent first)
        for entry_sig, glyph in reversed(self.current_buffer):
            if entry_sig == sig:
                return glyph
        # Then try previous bifolio with probability p_cross_bifolio
        if self.p_cross_bifolio > 0 and random.random() < self.p_cross_bifolio:
            for entry_sig, glyph in reversed(self.previous_buffer):
                if entry_sig == sig:
                    return glyph
        return None

    def push(self, sig: tuple, glyph: str) -> None:
        """Store a (sig, glyph) pair in the current bifolio buffer."""
        self.current_buffer.append((sig, glyph))

    def __len__(self) -> int:
        return len(self.current_buffer)


# === Deck-draw helper ===
def _next_table(
    deck: list[str], deck_index: int, use_78: bool
) -> tuple[str, list[str], int]:
    """Draw the next table from ``deck``, refilling it if exhausted.

    Returns ``(table, deck, deck_index)`` so callers can rebind the
    mutable deck/index state in one line.
    """
    if deck_index >= len(deck):
        deck = create_card_deck(use_78)
        deck_index = 0
    table = deck[deck_index]
    deck_index += 1
    return table, deck, deck_index


# === Bifolio encryption helper ===
def _encrypt_bifolio(
    bifolio_ngrams: list[str],
    tables: dict,
    glyph_map: dict,
    use_78: bool,
    deck: list[str],
    deck_index: int,
    memory: BifolioMemory,
    p_reuse: float,
) -> tuple[list[str], list[str], int]:
    """Encrypt one bifolio's ngrams with bifolio-scoped reuse.

    Returns (ciphertext_tokens, updated_deck, updated_deck_index).
    The deck and deck_index are threaded through so the card sequence
    is continuous across bifolia within a quire.
    """
    ciphertext: list[str] = []

    for token in bifolio_ngrams:
        sig = _plain_sig(token)

        # Reuse hot path
        cached_glyph = memory.lookup(sig)
        if cached_glyph is not None:
            if p_reuse >= 1.0 or (p_reuse > 0.0 and random.random() < p_reuse):
                ciphertext.append(cached_glyph)
                continue

        # Fresh draw
        if len(token) == 1:
            # === Unigram ===
            table, deck, deck_index = _next_table(deck, deck_index, use_78)
            code = tables[table][("unigram", token)]
            glyph = glyph_map.get(code, code)
            ciphertext.append(glyph)
            memory.push(sig, glyph)
        else:
            # === Bigram (two independent table draws) ===
            a, b = token[0], token[1]
            if UNAMBIGUOUS:
                # === Ambiguity-safe bigram ===
                accepted = False
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
                    memory.push(sig, combined)
                    accepted = True
                    break

                if not accepted:
                    # Exhausted retries; emit the last attempt to avoid deadlock.
                    ciphertext.append(glyph_prefix + glyph_suffix)
            else:
                # === Standard bigram (no collision checks) ===
                table_prefix, deck, deck_index = _next_table(
                    deck, deck_index, use_78
                )
                code_prefix = tables[table_prefix][("prefix", a)]
                glyph_prefix = glyph_map.get(code_prefix, code_prefix)

                table_suffix, deck, deck_index = _next_table(
                    deck, deck_index, use_78
                )
                code_suffix = tables[table_suffix][("suffix", b)]
                glyph_suffix = glyph_map.get(code_suffix, code_suffix)

                combined = glyph_prefix + glyph_suffix
                ciphertext.append(combined)
                memory.push(sig, combined)

    return ciphertext, deck, deck_index


# === Full encryption function ===
def encrypt_naibbe_quire(
    plaintext: str,
    tables: dict,
    glyph_map: dict,
    use_78: bool = False,
    bifolia_per_quire: int = 5,
    tokens_per_page: int = 160,
    p_reuse: float = 0.3,
    p_cross_bifolio: float = 0.1,
    pre_plaintext_file=None,
) -> list[str]:
    """Encrypt plaintext with quire-based bifolio structure.

    The plaintext is respaced, split into quires and bifolia, rearranged
    from reading order to bifolio encryption order, encrypted with
    bifolio-scoped glyph reuse, then rearranged back to reading order.

    Parameters
    ----------
    plaintext : str
        Pre-normalized plaintext (call clean_line upstream).
    tables : dict
        Substitution tables.
    glyph_map : dict
        Placeholder to glyph mapping.
    use_78 : bool
        Use the 78-card deck.
    bifolia_per_quire : int
        Number of bifolia per quire (default 5).
    tokens_per_page : int
        Tokens per page (default 160, ~29 lines x ~5.5 tokens/line).
    p_reuse : float
        Probability of reusing a cached glyph on a buffer hit (0.0-1.0).
    p_cross_bifolio : float
        Probability of looking in the previous bifolio's buffer (0.0-1.0).
    pre_plaintext_file : file-like, optional
        If given, the respaced plaintext is written to it.
    """
    # Validation
    if bifolia_per_quire < 1:
        raise ValueError(
            f"bifolia_per_quire must be >= 1, got {bifolia_per_quire}"
        )
    if tokens_per_page < 1:
        raise ValueError(
            f"tokens_per_page must be >= 1, got {tokens_per_page}"
        )
    if not (0.0 <= p_reuse <= 1.0):
        raise ValueError(
            f"p_reuse must be in [0.0, 1.0], got {p_reuse}"
        )
    if not (0.0 <= p_cross_bifolio <= 1.0):
        raise ValueError(
            f"p_cross_bifolio must be in [0.0, 1.0], got {p_cross_bifolio}"
        )

    ngrams = respace_plaintext(plaintext, pre_plaintext_file)
    quire_size = 4 * bifolia_per_quire * tokens_per_page

    # Split into quires
    quires = [ngrams[i:i + quire_size] for i in range(0, len(ngrams), quire_size)]

    all_ciphertext: list[str] = []

    for quire_ngrams in quires:
        # Split into pages
        pages = [
            quire_ngrams[i:i + tokens_per_page]
            for i in range(0, len(quire_ngrams), tokens_per_page)
        ]

        # Calculate actual number of bifolia (may be fewer for the last quire)
        n_bif = max(1, (len(pages) + 3) // 4)

        # Pad pages to fill complete bifolia
        while len(pages) < 4 * n_bif:
            pages.append([])

        # Initialize memory and deck for this quire
        memory = BifolioMemory(p_cross_bifolio)
        deck = create_card_deck(use_78)
        deck_index = 0

        # Allocate ciphertext slots in reading order
        quire_ciphertext: list[list[str] | None] = [None] * len(pages)

        # Encrypt bifolio by bifolio (in encryption order)
        for bifolio_idx in range(n_bif):
            memory.new_bifolio()

            # Gather the 4 pages of this bifolio (in encryption order)
            bifolio_pages_ngrams: list[str] = []
            page_reading_indices: list[int] = []
            for page_in_bifolio in range(4):
                reading_page = _bifolio_to_page(bifolio_idx, page_in_bifolio, n_bif)
                if reading_page < len(pages):
                    bifolio_pages_ngrams.extend(pages[reading_page])
                    page_reading_indices.append(reading_page)

            # Encrypt this bifolio's ngrams
            bifolio_ciphertext, deck, deck_index = _encrypt_bifolio(
                bifolio_pages_ngrams, tables, glyph_map, use_78,
                deck, deck_index, memory, p_reuse,
            )

            # Split the ciphertext back into page-sized chunks
            # and place them at their reading-order positions
            token_offset = 0
            for reading_page in page_reading_indices:
                page_token_count = len(pages[reading_page])
                page_ct = bifolio_ciphertext[token_offset:token_offset + page_token_count]
                quire_ciphertext[reading_page] = page_ct
                token_offset += page_token_count

        # Concatenate pages in reading order
        for page_ct in quire_ciphertext:
            if page_ct is not None:
                all_ciphertext.extend(page_ct)

    return all_ciphertext


# === File-level encryption driver (shared by CLI and eval) =================
def iter_encrypted_lines(
    input_path: str,
    use_78: bool,
    bifolia_per_quire: int,
    tokens_per_page: int,
    p_reuse: float,
    p_cross_bifolio: float,
    pre_plaintext_file=None,
):
    """Yield ``(cleaned, tokens)`` for each line of ``input_path``.

    The full file is encrypted as one block (the bifolio rearrangement
    requires the complete token sequence), then tokens are yielded
    line-by-line using the original line boundaries.
    """
    # Read all lines and clean them
    all_cleaned: list[str] = []
    with open(input_path, "r", encoding="utf-8") as fin:
        for line in fin:
            cleaned = clean_line(line)
            if cleaned:
                all_cleaned.append(cleaned)
            else:
                all_cleaned.append("")

    # Concatenate all cleaned lines into one plaintext
    full_plaintext = "".join(all_cleaned)

    # Encrypt the full plaintext as one block
    all_tokens = encrypt_naibbe_quire(
        full_plaintext,
        naibbe_tables,
        placeholder_to_glyph,
        use_78=use_78,
        bifolia_per_quire=bifolia_per_quire,
        tokens_per_page=tokens_per_page,
        p_reuse=p_reuse,
        p_cross_bifolio=p_cross_bifolio,
        pre_plaintext_file=pre_plaintext_file,
    )

    # Yield the concatenated plaintext and all tokens as one block
    # (the eval joins them all anyway, so one yield is sufficient)
    if all_tokens:
        yield full_plaintext, all_tokens


# === CLI ===
def build_parser() -> argparse.ArgumentParser:
    """Build the :mod:`argparse` parser for the quire CLI."""
    p = argparse.ArgumentParser(
        prog="naibbe-quire",
        description=(
            "Naibbe cipher generator with quire-based bifolio encryption. "
            "Pages are encrypted in bifolio order and rearranged back to "
            "reading order, so reuse within a bifolio produces long-range "
            "correlations across pages."
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
        "--bifolia-per-quire",
        type=int,
        default=5,
        help="Number of bifolia per quire (>= 1). Default 5.",
    )
    p.add_argument(
        "--tokens-per-page",
        type=int,
        default=160,
        help="Tokens per page (>= 1). Default 160.",
    )
    p.add_argument(
        "--p-reuse",
        type=float,
        default=0.3,
        help="Probability of reusing a cached glyph on a buffer hit "
        "(0.0-1.0).",
    )
    p.add_argument(
        "--p-cross-bifolio",
        type=float,
        default=0.1,
        help="Probability of looking in the previous bifolio's buffer "
        "(0.0-1.0).",
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
    """Entry point: encrypt an input file with quire-based bifolio structure."""
    args = parse_args(argv)

    if args.seed is not None:
        random.seed(args.seed)

    if args.bifolia_per_quire < 1:
        raise ValueError(
            f"--bifolia-per-quire must be >= 1, got {args.bifolia_per_quire}"
        )
    if args.tokens_per_page < 1:
        raise ValueError(
            f"--tokens-per-page must be >= 1, got {args.tokens_per_page}"
        )
    if not (0.0 <= args.p_reuse <= 1.0):
        raise ValueError(
            f"--p-reuse must lie in [0.0, 1.0], got {args.p_reuse}"
        )
    if not (0.0 <= args.p_cross_bifolio <= 1.0):
        raise ValueError(
            f"--p-cross-bifolio must lie in [0.0, 1.0], "
            f"got {args.p_cross_bifolio}"
        )

    with open(args.output, "w", encoding="utf-8") as fout, \
         open(args.respaced_output, "w", encoding="utf-8") as frespace, \
         open(args.pre_plaintext_output, "w", encoding="utf-8") as fplain:

        for cleaned, encrypted_tokens in iter_encrypted_lines(
            args.input, args.use_78,
            args.bifolia_per_quire, args.tokens_per_page,
            args.p_reuse, args.p_cross_bifolio,
            fplain,
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

    print(
        f"Quire stats: bifolia_per_quire={args.bifolia_per_quire}, "
        f"tokens_per_page={args.tokens_per_page}, "
        f"p_reuse={args.p_reuse}, "
        f"p_cross_bifolio={args.p_cross_bifolio}"
    )


if __name__ == "__main__":
    main(sys.argv[1:])
