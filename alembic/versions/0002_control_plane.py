"""Add identities, cases, append-only metadata events, and leased jobs."""

from alembic import op
import sqlalchemy as sa


revision = "0002_control_plane"
down_revision = "0001_initial_auth_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("subject", sa.String(256), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
    )
    # Preserve old token owners and map the initial operator spelling to analyst.
    op.execute("INSERT INTO users (subject, created_at) SELECT subject, MIN(issued_at) FROM auth_tokens GROUP BY subject")
    op.execute("UPDATE auth_tokens SET role = 'analyst' WHERE role = 'operator'")
    with op.batch_alter_table("auth_tokens") as batch:
        batch.create_foreign_key("fk_auth_tokens_subject_users", "users", ["subject"], ["subject"])
        batch.create_check_constraint("ck_auth_tokens_role", "role IN ('viewer', 'analyst', 'approver', 'admin', 'worker')")
        batch.create_check_constraint("ck_auth_tokens_expiry", "expires_at > issued_at")

    op.create_table(
        "cases",
        sa.Column("case_id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(256), sa.ForeignKey("users.subject"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("state = 'NEEDS_EVIDENCE'", name="ck_cases_state"),
        sa.CheckConstraint("reason = 'SECURITY_ENGINE_NOT_IMPLEMENTED'", name="ck_cases_reason"),
    )
    op.create_index("ix_cases_created_at", "cases", ["created_at", "case_id"])
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.case_id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("requested_by", sa.String(256), sa.ForeignKey("users.subject"), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(64), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("lease_id", sa.String(36)),
        sa.Column("lease_owner_token_id", sa.String(36), sa.ForeignKey("auth_tokens.token_id")),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("outcome", sa.String(32)),
        sa.UniqueConstraint("requested_by", "idempotency_key_hash", name="uq_jobs_request_key"),
        sa.CheckConstraint("kind = 'INVESTIGATION'", name="ck_jobs_kind"),
        sa.CheckConstraint("status IN ('QUEUED', 'LEASED', 'COMPLETED')", name="ck_jobs_status"),
        sa.CheckConstraint("attempts >= 0", name="ck_jobs_attempts"),
        sa.CheckConstraint("reason = 'SECURITY_ENGINE_NOT_IMPLEMENTED'", name="ck_jobs_reason"),
        sa.CheckConstraint(
            "status != 'LEASED' OR (lease_id IS NOT NULL AND lease_owner_token_id IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="ck_jobs_active_lease",
        ),
        sa.CheckConstraint(
            "(status = 'COMPLETED' AND completed_at IS NOT NULL AND outcome IS NOT NULL AND outcome = 'UNSUPPORTED') OR "
            "(status != 'COMPLETED' AND completed_at IS NULL AND outcome IS NULL)",
            name="ck_jobs_completion",
        ),
    )
    op.create_index("ix_jobs_claim", "jobs", ["status", "lease_expires_at", "created_at"])
    op.create_table(
        "audit_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_id", sa.String(36), nullable=False, unique=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.case_id"), nullable=False),
        sa.Column("actor", sa.String(256), sa.ForeignKey("users.subject"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_audit_events_case_sequence", "audit_events", ["case_id", "sequence"])
    if op.get_bind().dialect.name == "sqlite":
        for operation in ("UPDATE", "DELETE"):
            op.execute(
                f"CREATE TRIGGER audit_events_no_{operation.lower()} BEFORE {operation} ON audit_events "
                "BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END"
            )
    elif op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE FUNCTION counterseal_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'audit events are append-only'; END; $$"
        )
        op.execute(
            "CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE OR TRUNCATE "
            "ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION counterseal_audit_append_only()"
        )


def downgrade() -> None:
    op.drop_table("audit_events")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION counterseal_audit_append_only()")
    op.drop_table("jobs")
    op.drop_table("cases")
    with op.batch_alter_table("auth_tokens") as batch:
        batch.drop_constraint("ck_auth_tokens_expiry", type_="check")
        batch.drop_constraint("ck_auth_tokens_role", type_="check")
        batch.drop_constraint("fk_auth_tokens_subject_users", type_="foreignkey")
    op.execute("UPDATE auth_tokens SET role = 'operator' WHERE role = 'analyst'")
    op.drop_table("users")
