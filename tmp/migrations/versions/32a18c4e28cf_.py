"""empty message

Revision ID: 32a18c4e28cf
Revises: 7d0c95efe411
Create Date: 2019-10-21 14:38:05.592533

"""

# revision identifiers, used by Alembic.
revision = '32a18c4e28cf'
down_revision = '7d0c95efe411'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('confirmed', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'confirmed')
    # ### end Alembic commands ###
