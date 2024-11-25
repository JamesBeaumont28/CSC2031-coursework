"""empty message

Revision ID: b970d8cc5635
Revises: 63ebff672d70
Create Date: 2024-11-23 16:03:25.965861

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b970d8cc5635'
down_revision = '63ebff672d70'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_active', sa.Boolean(), nullable=False))
        batch_op.drop_column('active')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('active', sa.BOOLEAN(), nullable=False))
        batch_op.drop_column('is_active')

    # ### end Alembic commands ###