-- The same output hash can be on chain more than once (created, spent, created
-- again), and one output can belong to two accounts, so an active output row is
-- one instance: (account, hash, block it was mined in). Re-reading a block finds
-- the existing row through this index instead of inserting a second one.
DROP INDEX IF EXISTS idx_outputs_output_hash_active;
CREATE UNIQUE INDEX idx_outputs_account_hash_block_active
    ON outputs(account_id, output_hash, mined_in_block_hash) WHERE deleted_at IS NULL;

-- idx_outputs_tx_id_active stays global: displayed_transactions.id is a global
-- key filled from outputs.tx_id, and the tx_id derivation steps past any id an
-- active row of any account already holds (two accounts can share a view key).

-- Every scan credit and debit first looks for an existing one of its cause.
CREATE INDEX idx_balance_changes_caused_by_output
    ON balance_changes(caused_by_output_id) WHERE caused_by_output_id IS NOT NULL;
CREATE INDEX idx_balance_changes_caused_by_input
    ON balance_changes(caused_by_input_id) WHERE caused_by_input_id IS NOT NULL;
