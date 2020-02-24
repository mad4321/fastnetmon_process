__all__ = ['init_db','store_attack_host','remove_attack_host','get_attack_host']

import sqlite3
import logging
import my_fastnetmon.config as config

logger = logging.getLogger("log")

conn = sqlite3.connect(config.SQLITE_DB)
c = conn.cursor()

def init_db():
    c.execute(" SELECT count(name) FROM sqlite_master WHERE type='table' AND name='host_attacks' ")
    if c.fetchone()[0]==0 :
        c.execute(" CREATE TABLE 'host_attacks' (ip TEXT, network TEXT, attack_type TEXT, rule TEXT, datetime TEXT)")
    c.execute(" SELECT count(name) FROM sqlite_master WHERE type='table' AND name='network_attacks' ")
    if c.fetchone()[0]==0 :
        c.execute(" CREATE TABLE 'network_attacks' (network TEXT, attack_type TEXT, rule TEXT, datetime TEXT)")
    conn.commit()
    return

def store_attack_host(ip,network,attack_type,flow):
    c.execute('''INSERT INTO 'host_attacks' VALUES (?,?,?,?,?)''',(ip,network,attack_type,flow,''))
    conn.commit()
    return

def remove_attack_host(ip):
    c.execute("DELETE FROM 'host_attacks' WHERE ip = ?",[(ip)])
    conn.commit()
    return 

def get_attack_host(ip):
    c.execute("SELECT rule FROM 'host_attacks' WHERE ip = ?",[(ip)])
    return c.fetchall()

def remove_attack_network(network):
    return

def get_attack_network(network):
    return

def store_attack_network(network):
    return

