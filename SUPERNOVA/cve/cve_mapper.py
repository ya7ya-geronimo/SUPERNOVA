#!/usr/bin/env python3
"""
SUPERNOVA CVE Mapper
Maps open ports and detected services to CVEs
"""

from cve.cve_database import CVEDatabase


class CVEMapper:

    def __init__(self):

        self.db = CVEDatabase()


    def map_service(self, service_name, port):

        """
        Map single service to CVEs
        """

        return self.db.find_by_service(service_name, port)


    def map_scan_results(self, scan_results):

        """
        Add CVE info to scan results
        """

        for host in scan_results.get("hosts", []):

            for port in host.get("open_ports", []):

                service = port.get("service")
                port_number = port.get("port")

                cves = self.map_service(service, port_number)

                port["cves"] = cves

        return scan_results
