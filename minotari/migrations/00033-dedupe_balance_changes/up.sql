-- A balance change caused by an output or an input must exist at most once.
--
-- `balance_changes` is the sole source of an account's total, but nothing in the
-- schema stopped the same output/input from being credited or debited repeatedly.
-- The scanner re-presents blocks in normal operation (the continuous scan rewinds
-- one block per poll cycle) and a base node can repeat an input hash within a
-- block, so duplicates were reachable without any tampering — each one silently
-- moving the reported balance.
--
-- Reversal rows are excluded from the constraint: a reorg marks the original row
-- reversed and appends a matching `is_reversal` row against the same id, and a
-- re-mine records against a fresh output/input row (the soft-delete indexes are
-- partial on `deleted_at IS NULL`), so genuine history never collides.

-- Drop any existing duplicates first, keeping the earliest row for each cause.
DELETE FROM balance_changes
WHERE caused_by_output_id IS NOT NULL
  AND is_reversal = 0
  AND id NOT IN (
      SELECT MIN(id) FROM balance_changes
      WHERE caused_by_output_id IS NOT NULL AND is_reversal = 0
      GROUP BY caused_by_output_id
  );

DELETE FROM balance_changes
WHERE caused_by_input_id IS NOT NULL
  AND is_reversal = 0
  AND id NOT IN (
      SELECT MIN(id) FROM balance_changes
      WHERE caused_by_input_id IS NOT NULL AND is_reversal = 0
      GROUP BY caused_by_input_id
  );

CREATE UNIQUE INDEX IF NOT EXISTS idx_balance_changes_output_unique
    ON balance_changes(caused_by_output_id)
    WHERE caused_by_output_id IS NOT NULL AND is_reversal = 0;

CREATE UNIQUE INDEX IF NOT EXISTS idx_balance_changes_input_unique
    ON balance_changes(caused_by_input_id)
    WHERE caused_by_input_id IS NOT NULL AND is_reversal = 0;
