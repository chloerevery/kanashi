import os
import sys
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

class PacketInfo:
    def __init__(self, dest_IP, src_IP, compromised, time_classified_utc, description, action, success, packet_ID):
        self.dest_IP = dest_IP
        self.src_IP = src_IP
        self.compromised = compromised
        self.time_classified_utc = time_classified_utc
        self.description = description
        self.action = action
        self.success = success
        self.packet_ID = packet_ID


@app.route('/')
def starting_page():
    packet_info = connect_db()
    return render_template('index.html', 
       packet_info = packet_info)

def connect_db():
    """Connects to the specific database and returns list of packet data and decisions."""
    con = None

    packet_info = []

    try:
        con = sqlite3.connect(app.config['DATABASE'])
        
        cur = con.cursor()

        cur.execute('SELECT * FROM packets') # WHERE SrcIP = "10:a5:d0:e2:ed:35"') #  WHERE MAC = galaxy_MAC
        
        data = cur.fetchall()
        for packet in data:
            print "heyo"
            print packet[3]
            new_packet = PacketInfo(packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7])
            packet_info.append(new_packet)          
        return packet_info
    except sqlite3.Error, e:
        
        print "Error %s:" % e.args[0]
        sys.exit(1)
        return packet_info
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
    
    app.run()


