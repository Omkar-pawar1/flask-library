"""fixed section model

Revision ID: f8d1f91c1cda
Revises: 
Create Date: 2024-01-30 10:20:05.346494

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f8d1f91c1cda'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('section', schema=None) as batch_op:
        batch_op.alter_column('description',
               existing_type=sa.DATETIME(),
               type_=sa.String(length=500),
               nullable=False)
        batch_op.alter_column('date_created',
               existing_type=sa.INTEGER(),
               type_=sa.DateTime(),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('section', schema=None) as batch_op:
        batch_op.alter_column('date_created',
               existing_type=sa.DateTime(),
               type_=sa.INTEGER(),
               existing_nullable=True)
        batch_op.alter_column('description',
               existing_type=sa.String(length=500),
               type_=sa.DATETIME(),
               nullable=True)

    # ### end Alembic commands ###
