"""SecureBuild CI/CD Security Gate - Flask Dashboard Application Factory"""

from flask import Flask
import os
import sys

# Ensure the parent directory is on the path so engine modules are importable
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


def _resolve_db_path() -> str:
    env_path = os.getenv('DB_PATH')
    if env_path:
        return env_path

    # Try to load securebuild.yaml from the project root
    for candidate in ('securebuild.yaml', 'securebuild.yml'):
        config_path = os.path.join(_project_root, candidate)
        if os.path.exists(config_path):
            try:
                from engine.config import SecureBuildConfig
                cfg = SecureBuildConfig.from_file(config_path)
                db_path = getattr(cfg, 'database_path', None)
                if db_path:
                    # Resolve relative paths from the project root
                    if not os.path.isabs(db_path):
                        db_path = os.path.join(_project_root, db_path)
                    return db_path
            except Exception:
                pass
            break

    # Fall back to the engine's default: securebuild.db in the project root
    return os.path.join(_project_root, 'securebuild.db')


def create_app(config=None):
    app = Flask(
        __name__,
        template_folder='templates',
        static_folder='static'
    )

    # Use FLASK_SECRET_KEY env var, or fall back to a stable dev key
    secret_key = os.getenv('FLASK_SECRET_KEY', 'securebuild-dashboard-dev-key-change-in-prod')
    app.config['SECRET_KEY'] = secret_key

    # Resolve DB path from config / env — same logic as the CLI
    app.config['DB_PATH'] = _resolve_db_path()

    # Apply any custom config overrides
    if config:
        app.config.update(config)

    # Register blueprints
    from dashboard.routes.home import home_bp
    from dashboard.routes.runs import runs_bp

    app.register_blueprint(home_bp)
    app.register_blueprint(runs_bp)

    return app
