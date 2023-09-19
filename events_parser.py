import re
import logging
from datetime import datetime


class EventParser:
    """
    This class recieves a dictionary of events with records from auditd.log.
    Then it extracts the most important event attribute from SYSCALL and PATH records.
    """

    def __init__(self, events):
        self.events = events
        self.parsed_events = []

    def extract_info(self, log_string, event_id):
        """
        This method utilizes regular expressions to parse a SYSCALL record.
        """
        # Regular expressions to extract specific information
        # Regular expressions to extract specific information
        syscall_id_pattern = r'syscall=(\d+)'
        syscall_pattern = r'SYSCALL=(\w+)'
        exe_pattern = r'exe="([^"]+)"'
        time_pattern = r'audit\((\d+\.\d+):(\d+)\)'
        key_pattern = r'key="([^"]+)"'
        uid_pattern = r'UID="(\w+)"'
        comm_pattern = r'comm="([^"]+)"'
        auid_pattern = r'auid=(\d+)'

        # Extract syscall number
        syscall_id_match = re.search(syscall_id_pattern, log_string)
        syscall_id = int(syscall_id_match.group(1)) if syscall_id_match else None
    
        # Extract syscall name
        syscall_match = re.search(syscall_pattern, log_string)
        syscall = syscall_match.group(1) if syscall_match else None

        # Extract time in human-readable form
        time_match = re.search(time_pattern, log_string)
        if time_match:
            timestamp = float(time_match.group(1))
            event_time = datetime.fromtimestamp(timestamp) #.strftime('%Y-%m-%d %H:%M:%S')
        else:
            event_time = None

        # Extract exe
        exe_match = re.search(exe_pattern, log_string)
        exe = exe_match.group(1) if exe_match else None

        # Extract key and uid
        key_match = re.search(key_pattern, log_string)
        key = key_match.group(1) if key_match else None

        uid_match = re.search(uid_pattern, log_string)
        uid = uid_match.group(1) if uid_match else None
    
        # Extract comm
        comm_match = re.search(comm_pattern, log_string)
        comm = comm_match.group(1) if comm_match else None

        # Extract auid
        auid_match = re.search(auid_pattern, log_string)
        auid = int(auid_match.group(1)) if auid_match else None

        return {
            'event_id': event_id,
            'syscall': syscall,
            'syscall_id':syscall_id,
            'datetime': event_time,
            'exe': exe,
            'key': key,
            'uid': uid,
            'auid': auid,
            'comm':comm
        }


    def parse_events(self):
        """
        For each event find needed records and parse them, to obtain important attributes.
        """
        for event_id, records in self.events.items():
            for record in records:
                if 'type=SYSCALL' in record and ('key=(null)' not in record):
                    try:
                        parsed_event = self.extract_info(record, event_id)
                        self.parsed_events.append(parsed_event)
                    except Exception as e:
                        logging.error(str(e)) 
        
    
    def get_parsed_events(self):
        try:
            self.parse_events()
        except Exception as e:
            logging.error(str(e))
        if self.parse_events:
            logging.info('events successfully parsed')
            return self.parsed_events
        else:
            logging.error('no parsed events')
            raise Exception
