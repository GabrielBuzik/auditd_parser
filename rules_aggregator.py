import re
import logging
from datetime import datetime

import pandas as pd


class RulesAggregator:
    """
    Calculates some statistcs on rules using pandas library.
    Uses rule key, provided in auditd.rule with "-k".
    """
    def __init__(self, parsed_events):
        self.parsed_events = parsed_events
        self.rule_summary = None

    def aggregate_by_rule(self):

        try:
            df = pd.DataFrame(self.parsed_events)

            self.rule_summary = df.groupby('key').agg(
                num_events=pd.NamedAgg(column='event_id', aggfunc='count'),
                first_event_time=pd.NamedAgg(column='datetime', aggfunc='min'),
                last_event_time=pd.NamedAgg(column='datetime', aggfunc='max'),
                unique_users=pd.NamedAgg(column='uid', aggfunc=lambda x: x.nunique())
            )

            return self.rule_summary

        except Exception as e:
            logging.error(str(e))
            return None
        
    def create_statistics_cvs(self):
        """
        Save statistics of aggregation to cvs.
        """
        if self.rule_summary is None:
            logging.error('statistics not calculated')
            return None
        self.rule_summary.to_csv('rule_statistics.csv')
        logging.info('statistics written to cvs')
        return True