import os
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, abort, \
    render_template, flash

app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'src/mysqlite_3'),
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

galaxy_MAC = "10:a5:d0:e2:ed:35"
alexa_MAC = "aa:bb:cc:dd:ee:ff"

@app.route('/')
def starting_page():
	return render_template('index.html')

def connect_db():
    """Connects to the specific database."""
    con = None

    try:
        con = sqlite3.connect(app.config['DATABASE'])
        print "herea"
        
        cur = con.cursor()    
        print "hereb"

        cur.execute('SELECT * FROM packets') # WHERE SrcIP = "10:a5:d0:e2:ed:35"') #  WHERE MAC = galaxy_MAC
        print "herec"

        
        data = cur.fetchall()
        
        print "Query results: %s" % data   
        print "data[0]"
        print data[0][0]             
        
    except sqlite3.Error, e:
        
        print "Error %s:" % e.args[0]
        sys.exit(1)
        
    finally:
        
        if con:
            con.close()
    # rv = sqlite3.connect(app.config['DATABASE'])

    # rv.row_factory = sqlite3.Row
    # return rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.debug=True
    connect_db()
    app.run()


