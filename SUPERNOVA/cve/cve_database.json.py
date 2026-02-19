#!/usr/bin/env python3
"""
SUPERNOVA CVE Database Loader
Handles loading and retrieving CVE entries
"""

import json
import os


class CVEDatabase:

    def __init__(self):

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.db_file = os.path.join(base_dir, "cve_database.json")

        self.cve_data = {}

        self._load()


    def _load(self):
        """
        Load CVE JSON file
        """

        if not os.path.exists(self.db_file):

            print("[!] CVE database file not found")
            self.cve_data = {}
            return


        try:

            with open(self.db_file, "r", encoding="utf-8") as f:

                self.cve_data = json.load(f)

            print(f"[+] CVE Database loaded: {len(self.cve_data)} entries")


        except Exception as e:

            print(f"[ERROR] Failed to load CVE database: {e}")
            self.cve_data = {}


    def get_all(self):

        return self.cve_data


    def get(self, cve_id):

        return self.cve_data.get(cve_id)


    def find_by_service(self, service_name, port):

        """
        Find CVEs matching service and port
        """

        results = []

        for cve_id, data in self.cve_data.items():

            if (
                data.get("service", "").lower() == service_name.lower()
                and data.get("port") == port
            ):

                results.append({

                    "cve_id": cve_id,
                    "description": data.get("description"),
                    "severity": data.get("severity")

                })

        return results
