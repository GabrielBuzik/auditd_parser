import re
import os
import json
import logging
from datetime import datetime

import pandas as pd

from events_parser import EventParser
from sqlite_writer import SQLiteWriter
from rules_aggregator import RulesAggregator


with open('config.json', 'r') as config_file:
    config = json.load(config_file)

log_file_path = config['log_file_path']
directory_path = config['directory_path']
database_file = config['database_file']

# log_file_path = '/var/log/audit/audit.log'
# directory_path = '/var/log/audit/'
# database_file = "my_system_events.db"

# using logging (8), info and errors are saved to a log file
logging.basicConfig(
    filename='audit_parser.log',
    level=logging.INFO,
    format='%(asctime)s: %(levelname)s - %(message)s'
)


def get_log_paths(directory_path):
    files = os.listdir(directory_path)
    file_paths = []
    for file_name in files:
        file_path = os.path.join(directory_path, file_name)
        file_paths.append(file_path)
    logging.info(f'{file_paths} are the file paths')
    return file_paths


def read_auditd_file(log_file_path, last_event_time):
    """
    Read auditd.log file given path.
    Return dictionary of events with raw records.
    """
    events = {}
    try:
        with open(log_file_path, 'r') as log_file:

            for line in log_file:

                # Ignore checked lines
                # (5) Ensure that the program does not
                # store duplicate data from previous runs.
                time_match = re.search(r'(\d+\.\d+):(\d+)', line)
                time_sec = float(time_match.group(1))
                current_event_datetime = datetime.fromtimestamp(time_sec)

                # If current event happened before the last db event,
                # Do not include it
                if last_event_time is not None:
                    if current_event_datetime <= last_event_time:
                        continue
                
                # Get event id and map record to event id.
                match = re.match(r'.*audit\(\d+\.\d+:(\d+)\)', line)
                if match:
                    event_id = int(match.group(1))
                    events.setdefault(event_id, []).append(line.strip())

        return events
    
    except Exception as e:
        logging.error(str(e))
        return None


def main():

    # (6) get all log file paths
    log_files_paths = get_log_paths(directory_path)

    # (5) Ensure that the program does not
    # store duplicate data from previous runs.
    sqllite_writer =SQLiteWriter(database_file)
    last_event_time = sqllite_writer.get_time_of_latest_object()
    logging.info(f'The latest event from the db happened at {last_event_time}')

    # (1) read file and (2) analyze the auditd log files
    events = {}
    for log_file_path in log_files_paths:
        events.update(read_auditd_file(log_file_path, last_event_time))
        logging.info(
            f'now there are {len(events)} after file {log_file_path} reading'
        )
    event_parser = EventParser(events)
    parsed_events = event_parser.get_parsed_events()
    logging.info(
        f'{len(parsed_events)} events have been parsed.'
    )

    #(3) Aggregate the results for each rule/command.
    aggregator = RulesAggregator(parsed_events)
    statistics_by_rule = aggregator.aggregate_by_rule()
    aggregator.create_statistics_cvs()
    print('Statistics for each rule:')
    print(statistics_by_rule)
    logging.info(
        f'Statistics stage passed'
    )

    # (4) Store the parsed data in a local database, such as SQLite(stores parsed events)
    sqllite_writer.connect()
    sqllite_writer.write_new_events(parsed_events)
    logging.info(
        f'Finish SQL writing'
    )

if __name__ == "__main__":
    main()