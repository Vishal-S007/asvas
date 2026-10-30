from alembic import context
from sqlalchemy import create_engine

from asvas.config import get_settings

url = context.config.attributes.get("url") or get_settings().migration_database_url


def run() -> None:
    engine = create_engine(url)
    with engine.begin() as conn:
        context.configure(connection=conn)
        with context.begin_transaction():
            context.run_migrations()


run()
