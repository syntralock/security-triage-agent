"""Alembic migration environment."""

from logging.config import fileConfig

from alembic import context

from security_triage_agent.adapters.persistence.models import Base
from security_triage_agent.adapters.persistence.uow import create_engine
from security_triage_agent.config import Settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
target_metadata = Base.metadata


def database_url() -> str:
    """Resolve trusted runtime configuration, with an explicit programmatic override."""

    override = config.attributes.get("database_url")
    return str(override) if override is not None else Settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(database_url())
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
