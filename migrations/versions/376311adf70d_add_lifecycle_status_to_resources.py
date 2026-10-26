"""add_lifecycle_status_to_resources

Revision ID: 376311adf70d
Revises: a82df1b94c30
Create Date: 2026-10-19 11:54:51.458657

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '376311adf70d'
down_revision = 'a82df1b94c30'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add nullable status column first
    op.add_column('resources', sa.Column('status', sa.String(length=20), nullable=True))

    # 2. Backfill existing rows: approved=True -> 'approved'
    op.execute("UPDATE resources SET status = 'approved' WHERE approved = TRUE")

    # 3. Backfill existing rows: approved=False -> 'pending'
    op.execute("UPDATE resources SET status = 'pending' WHERE approved = FALSE OR approved IS NULL")

    # 4. Check for explicit audit evidence of rejection (if any existing resource ID has resource_rejected audit log)
    # Using safe SQL regex extraction compatible with PostgreSQL
    try:
        op.execute("""
            UPDATE resources
            SET status = 'rejected'
            WHERE approved = FALSE
              AND id IN (
                  SELECT CAST(substring(detail FROM '\\(ID ([0-9]+)\\)') AS INTEGER)
                  FROM activity_logs
                  WHERE action = 'resource_rejected'
                    AND detail ~ '\\(ID [0-9]+\\)'
              )
        """)
    except Exception:
        # Fallback for non-PostgreSQL dialects where regex substring may differ
        pass

    # 5. Alter column to NOT NULL with server default 'pending'
    op.alter_column('resources', 'status', existing_type=sa.String(length=20), nullable=False, server_default='pending')

    # 6. Add CHECK constraint and index for fast status filtering
    op.create_check_constraint('ck_resources_status', 'resources', "status IN ('pending', 'approved', 'rejected')")
    op.create_index('ix_resources_status', 'resources', ['status'], unique=False)


def downgrade():
    # 1. Synchronize legacy approved column from status before dropping
    # Note: Downgrade limitation: Boolean approved cannot distinguish 'pending' from 'rejected';
    # both map to approved=FALSE.
    op.execute("UPDATE resources SET approved = TRUE WHERE status = 'approved'")
    op.execute("UPDATE resources SET approved = FALSE WHERE status IN ('pending', 'rejected')")

    # 2. Drop index, constraint, and status column
    op.drop_index('ix_resources_status', table_name='resources')
    op.drop_constraint('ck_resources_status', 'resources', type_='check')
    op.drop_column('resources', 'status')
