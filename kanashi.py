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

macbook_ip = "192.168.1.14" # NOT ITS TRUE IP VALUE
alexa_ip = "207.46.107.149" # NOT ITS TRUE IP VALUE
devices = [macbook_ip, alexa_ip] # MODIFY THIS LIST TO INCLUDE NEW DEVICES AND CORRECT IP ADDRESSES

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
    all_packets = get_all_packets()
    packets_from_ip_a = get_packets_from_ip(devices[0])
    print("FROM IP A:")
    print(packets_from_ip_a)

    packets_from_ip_b = get_packets_from_ip(devices[1])
    packets_to_ip_a = get_packets_to_ip(devices[0])

    packets_to_ip_b = get_packets_to_ip(devices[1])

    return render_template('index.html', 
       all_packets=all_packets, packets_from_ip_a=packets_from_ip_a,  packets_from_ip_b= packets_from_ip_b,  packets_to_ip_a= packets_to_ip_a, packets_to_ip_b=packets_to_ip_b)

def get_all_packets():
    """Connects to the specific database and returns list of packet data and decisions."""
    con = None

    all_packets = []

    try:
        con = sqlite3.connect(app.config['DATABASE'])
        
        cur = con.cursor()

        cur.execute('SELECT * FROM packets ORDER BY TimeClassifiedUTC') # WHERE SrcIP = "10:a5:d0:e2:ed:35"') #  WHERE MAC = galaxy_MAC
        
        data = cur.fetchall()
        for packet in data:
            print "heyo"
            print packet
            new_packet = PacketInfo(packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7])
            all_packets.append(new_packet)          
        return all_packets
    except sqlite3.Error, e:
        
        print "Error %s:" % e.args[0]
        sys.exit(1)
        return all_packets
    finally:
        
        if con:
            con.close()

def get_packets_from_ip(src_ip):
    """Connects to the specific database and returns list of lists of packet data and decisions sent from an ip."""
    con = None

    packets_sent_by_device = []
    print "packets_sent_by_device"
    print packets_sent_by_device

    try:
        con = sqlite3.connect(app.config['DATABASE'])
        
        cur = con.cursor()

        for i in range(0, len(devices)):
            stmt = 'SELECT * FROM packets WHERE SrcIP = "%s";' % src_ip
            print ("stmt:")
            print stmt
            cur.execute(stmt) # WHERE SrcIP = "10:a5:d0:e2:ed:35"') #  WHERE MAC = galaxy_MAC
        
            data = cur.fetchall()
            for packet in data:
                print packet
                new_packet = PacketInfo(packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7])
                packets_sent_by_device.append(new_packet)   
        print "PACKETS SENT BY DEVICE:"
        print packets_sent_by_device       
        return packets_sent_by_device
    except sqlite3.Error, e:
        
        print "Error %s:" % e.args[0]
        sys.exit(1)
        return packets_sent_by_device
    finally:
        
        if con:
            con.close()
        
def get_packets_to_ip(dst_ip):
    """Connects to the specific database and returns list of lists of packet data and decisions, grouped by device."""
    con = None

    packets_sent_to_device = []
    
    try:
        con = sqlite3.connect(app.config['DATABASE'])
        
        cur = con.cursor()

        for i in range(0, len(devices)):
            stmt = 'SELECT * FROM packets WHERE DstIP = "%s";' % dst_ip
            print ("stmt:")
            print stmt
            cur.execute(stmt) # WHERE SrcIP = "10:a5:d0:e2:ed:35"') #  WHERE MAC = galaxy_MAC
        
            data = cur.fetchall()
            for packet in data:
                print packet
                new_packet = PacketInfo(packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7])
                packets_sent_to_device.append(new_packet)          
        return packets_sent_to_device
    except sqlite3.Error, e:
        
        print "Error %s:" % e.args[0]
        sys.exit(1)
        return packets_sent_to_device
    finally:
        
        if con:
            con.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.debug=True
    
    app.run()


