import os
from flask_migrate import upgrade
from app.models import User, Role

COV = None
if os.environ.get('FLASK_COVERAGE'):
    import coverage
    COV = coverage.coverage(branch=True, include='app/*')
    COV.start()

import sys
import click
from flask_migrate import Migrate
from app import create_app, db
from app.models import User, Role, Follow, Post, Comment, Permission

app = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(app, db)




@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role, Follow=Follow,
    Post=Post, Comment=Comment, Permission=Permission)



@app.cli.command()
@click.option('--coverage/--no-coverage', default=False,
            help='Run tests under code coverage.')
def test(coverage):
    """Run unit tests"""
    if coverage and not os.environ.get('FLASK_COVERAGE'):
        import subprocess
        os.environ['FLASK_COVERAGE'] = '1'
        sys.exit(subprocess.call(sys.argv))
        #os.execvp(sys.executable, [sys.executable] + sys.argv)
    
    import unittest

    tests= unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)
    if COV:
        COV.stop()
        COV.save()
        print('Coverge Summary:')
        COV.report()
        basedir = os.path.abspath(os.path.dirname(__file__))
        covdir = os.path.join(basedir, 'tmp/coverage')
        COV.html_report(directory=covdir)
        print('HTML version: file://%s/index.html' % covdir)
        COV.erase()


# Performance test Not quite understand
@app.cli.command()
@click.option('--length', default=25,
            help='Number of functions to include in the profiler report.')
@click.option('--profile-dir', default=None,
            help='Directory where profiler data files are saved')
def profile(length, profile_dir):
    '''Start the application under the code profiler'''
    from werkzeug.contrib.profiler import ProfilerMiddleware
    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length], profile_dir=profile_dir)

    app.run(debug=False)


@app.cli.command()
def deploy():
    '''Run deployment tasks.'''
    #Update db
    upgrade()

    #Update new roles
    Role.insert_roles()

    #Make sure self follow
    User.add_self_follows()