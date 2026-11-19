-- Finds outputs whose spend a reorg removed (a soft-deleted input record).
CREATE INDEX idx_inputs_output_id_deleted ON inputs(output_id) WHERE deleted_at IS NOT NULL;
