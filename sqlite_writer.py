import re
import logging
import sqlite3
from datetime import datetime


class SQLiteWriter:
    """
    Performs all interactions with SQLite Database.
    """
    def __init__(self, database_file):
        self.database_file = database_file
        self.conn = None

    def connect(self):
        """
        Attempts to connect to SQLite database.
        """
        try:
            self.conn = sqlite3.connect(self.database_file)
            logging.info('Connected to SQLite')
        except sqlite3.Error as e:
            logging.error(str(e))

    def create_table_if_not_exist(self):
        """
        Creates a table for storing parsed event data in the database.
        """

        if not self.conn:
            logging.error('Not connected to DB')
            return None

        try:
            cur = self.conn.cursor()
            cur.execute('''
            CREATE TABLE IF NOT EXISTS events (
            event_id INTEGER,
            syscall TEXT,
            syscall_id INTEGER,
            datetime DATETIME,
            exe TEXT,
            key TEXT,
            uid TEXT,
            auid INTEGER,
            comm TEXT,
            UNIQUE (event_id, datetime))
            ''')
        except sqlite3.Error as e:
            logging.error(str(e))

    def write_new_events(self, parsed_events):
        """
        Query for storing events.
        Checks that an events has not been stored yet.
        """
        event_data = [(event['event_id'],
               event['syscall'],
               event['syscall_id'],
               event['datetime'].strftime('%Y-%m-%d %H:%M:%S.%f'),
               event['exe'],
               event['key'],
               event['uid'],
               event['auid'],
               event['comm']) for event in parsed_events]
        
        if not self.conn:
            logging.error('Not connected to DB')
            return None
        
        try:
            self.create_table_if_not_exist()
            cur = self.conn.cursor()
            cur.executemany('''
            INSERT INTO events (event_id, syscall, syscall_id, datetime, exe, key, uid, auid, comm)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', event_data)

            logging.info(f'{len(event_data)} events added to db')
            self.conn.commit()
        except sqlite3.Error as e:
            logging.error(str(e))

    def get_time_of_latest_object(self):
        """
        This method is used when reading lines at the begining.
        """
        sql_query = "SELECT MAX(datetime) FROM events"
        date_format = '%Y-%m-%d %H:%M:%S.%f'

        self.connect()

        try:
            cur = self.conn.cursor()
            cur.execute(sql_query)
            latest_time = cur.fetchone()[0]
            latest_datetime = datetime.strptime(latest_time, date_format)
            return latest_datetime
        except sqlite3.Error as e:
            logging.error(str(e))
            return None
