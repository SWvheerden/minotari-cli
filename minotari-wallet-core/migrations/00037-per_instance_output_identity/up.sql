-- The same output hash can be on chain more than once (created, spent, created
-- again), and one output can belong to two accounts, so an active output row is
-- one instance: (account, hash, block it was mined in). Re-reading a block finds
-- the existing row through this index instead of inserting a second one.
DROP INDEX IF EXISTS idx_outputs_output_hash_active;
CREATE UNIQUE INDEX idx_outputs_account_hash_block_active
    ON outputs(account_id, output_hash, mined_in_block_hash) WHERE deleted_at IS NULL;

-- tx_id is derived from the account's view key, which two accounts can share.
DROP INDEX IF EXISTS idx_outputs_tx_id_active;
CREATE UNIQUE INDEX idx_outputs_account_tx_id_active ON outputs(account_id, tx_id) WHERE deleted_at IS NULL;
