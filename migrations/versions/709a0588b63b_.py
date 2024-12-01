"""empty message

Revision ID: 709a0588b63b
Revises: a28620c0bc77
Create Date: 2024-12-01 18:06:56.072088

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '709a0588b63b'
down_revision = 'a28620c0bc77'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('userid', sa.Integer(), nullable=True),
    sa.Column('userRegTime', sa.DateTime(), nullable=False),
    sa.Column('recentLoginTime', sa.DateTime(), nullable=True),
    sa.Column('prevLoginTime', sa.DateTime(), nullable=True),
    sa.Column('latestIP', sa.String(length=15), nullable=False),
    sa.Column('prevIP', sa.String(length=15), nullable=False),
    sa.ForeignKeyConstraint(['userid'], ['users.id'], name=op.f('fk_logs_userid_users')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_logs'))
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('logs')
    # ### end Alembic commands ###
