import requests
import pathlib
from .exceptions import *
import json


class CriminalIP:


    def __init__(self, api_token=None):
        self.api_token = api_token
        self.base_url = 'https://api.criminalip.io/'


    def do_post(self, payload={}, headers={}, endpoint=''):
        try:

            if self.api_token is None:
                raise ApiKeyError("Api key not set.")

            headers.update({"x-api-key": f"{self.api_token}"})

            payload.update(payload)

            response = requests.post(
                url=self.base_url + endpoint,
                headers= headers,
                data=payload
            )

            return response.json()


        except Exception as e:
            print(f'Error Ocurred: {e}')


    def do_get(self, headers={}, endpoint='', params={}):
        try:

            if self.api_token is None:
                raise ApiKeyError("Api key not set.")
            
            headers.update({"x-api-key": f"{self.api_token}"})

            response = requests.get(
                url=self.base_url + endpoint,
                headers=headers,
                params=params
            )

            return response.json()

        except Exception as e:
            print(f'Error Ocurred: {e}')


    def account_info(self):
        """
        API for retrieving user information related to Criminal IP.
        """

        endpoint = '/v1/user/me'
        return self.do_post(endpoint=endpoint)


    def ip_asset_report(self, ip_address, full=False):
        """
        API for retrieving comprehensive data on a specific IP address, 
        including VPN IP status, Scanner IP status, open ports, connected domains, vulnerabilities, and more.
        """

        if full:

            params = {
                'ip':ip_address,
                'full':'true'
            }
            
            return self.do_get(endpoint="v1/asset/ip/report", params=params)
        else:
            params={'ip':ip_address}
            return self.do_get(endpoint="v1/asset/ip/report", params=params)



    def ip_assest_report_summary(self, ip_address):
        """
        API for retrieving summarized data, such as issues, risks, open ports, connections, and detection information for a specific IP address.
        """
        params = {'ip':ip_address}
        return self.do_get(endpoint='v1/asset/ip/report/summary', params=params)


    def ip_assest_summary(self, ip_address):
        """
        API for retrieving summarized information such as location data, ISP, owner, ASN, and other details for a specific IP address.
        """
        params={'ip':ip_address}
        return self.do_get(endpoint="v1/asset/ip/summary", params=params)


    def assest_search(self, query, offset):

        """
        This API retrieves asset search results with filters applied.
        """

        final_result = {}

        for iter in range(0, offset, 100):

            params = {
                'query': query,
                'offset': iter
            }

            results = self.do_get(endpoint='v1/asset/search', params=params)

            if not results or int(results.get('status')) != 200:
                break
            
            final_result.update(results)

        return final_result


    def ip_vpn(self, ip_address):
        """
        API for retrieving whether a specific IP address is being used as a VPN IP address.
        """

        params={'ip':ip_address}

        return self.do_get(endpoint="v1/ip/vpn", params=params)


    def ip_hosting(self, ip_address, full=False):
        """
        API for retrieving whether a specific IP address is being used as a hosting IP address.

        """
        params={'ip':ip_address,
                    'full': full}

        return self.do_get(endpoint='v1/ip/hosting', params=params)


    def ip_mal_info(self, ip_address):
        """
        This is an API for inquiring whether a specific IP address is a malicious IP address.
        """
        params = {'ip':ip_address}

        return self.do_get(endpoint='v2/feature/ip/malicious-info', params=params)


    def ip_privacy_threats(self, ip_address):
        """
        API for detecting whether webcams or IoT devices are exposed on a specific IP address.
        """

        params = {'ip':ip_address}

        return self.do_get(endpoint='v1/feature/ip/privacy-threat', params=params)


    def is_safe_dns_server(self, ip_address):
        """
        API for retrieving whether the DNS service of a specific IP address is secure.
        """

        params = {'ip':ip_address}

        return self.do_get(endpoint='v1/feature/ip/is_safe_dns_server', params=params)


    def ip_suspicious_info(self, ip_address):
        """
        API for retrieving data suspected to be malicious, which is associated with a specific IP address.
        """

        params = {'ip':ip_address}

        return self.do_get(endpoint='v2/feature/ip/suspicious-info', params=params)


    def banner_search(self, query, offset):
        """
        API for retrieving search results of banners using filters.
        """

        final_result = {}

        for iter in range(0, offset, 10):

            params = {
                'query': query,
                'offset': iter
            }

            results = self.do_get(endpoint='v1/banner/search', params=params)

            if not results or int(results.get('status')) != 200:
                break
            
            final_result.update(results)

        return final_result


    def banner_stats(self, query):
        """
        API for retrieving statistics of banner search results.

        """

        params = {'query':query}

        return self.do_get(endpoint='/v1/banner/stats', params=params)


    def domain_reports(self, query, offset):
        """
        This API retrieves a list of fully scanned domains based on a specific query. You can view the list of retrieved domains along with their scoring, country, and malicious domain information.
        """

        params = {'query':query,
                  'offset':offset}

        final_result = {}

        for iter in range(0, offset, 100):
            
            params = {
                'query': query,
                'offset': iter
            }

            results = self.do_get(endpoint='v1/domain/reports', params=params)

            if not results or int(results.get('status')) != 200:
                break
            
            final_result.update(results)

        return final_result


    # /v1/domain/reports/personal is not implemented yet.

    def get_domain_reports_by_id(self, id):
        """
        API for retrieving domain information for a specific scan_id.

        """

        return self.do_get(endpoint=f'v1/domain/reports/{id}')



    def get_domain_status_by_id(self, id):
        """
        API for checking whether there is a scan history for a specific domain.

        """

        return self.do_get(endpoint=f'/v1/domain/status/{id}')



    def domain_scan(self, domain):
        """
        API for determining the scan_id for initiating a new scan of a specific domain.
        """

        payload = {'query':domain}

        return self.do_post(payload=payload, endpoint='/v1/domain/scan')



    def domain_scan(self, domain):
            """
            API for retrieving security information such as phishing, vulnerabilities, and more for a specific domain in a confidential manner.
            """
    
            payload = {'query':domain}
    
            return self.do_post(payload=payload, endpoint='/v1/domain/scan/private')


    def domain_lite_report(self, query, offset):
        """
        This API retrieves a list of domains scanned with a specific query. You can view the list of retrieved domains and their scoring information.

        """

        params = {'query':query, 'offset':offset}

        final_result = {}

        for iter in range(0, offset, 100):

            params = {
                'query': query,
                'offset': iter
            }

            results = self.do_get(endpoint='/v1/domain/lite/reports', params=params)

            if not results or int(results.get('status')) != 200:
                break
            
            final_result.update(results)        

        return final_result


    def domain_lite_progress(self, scan_id):
        """
        This is an API for checking the progress of a Lite Scan.
        The progress can be indicated by the following numbers: -1, -2, and 0 to 100, each representing a specific state.
        """

        params = {'scan_id':scan_id}

        return self.do_get(endpoint='/v1/domain/lite/progress', params=params)



    def domain_lite_report_by_id(self, scan_id):
        """
        This API inquires about Domain Search Lite Scan results.
        """

        return self.do_get(endpoint=f'/v1/domain/lite/report/{scan_id}')


    def domain_lite_scan(self, domain):
        """
        This is an API for requesting a Lite Scan for a new URL in Domain Search.
It analyzes the threat information of the provided URL based on a quick collection of partial OSINT.
The scanning process takes an average of 2 to 5 seconds and may have relatively lower accuracy compared to a Full Scan.


        """

        payload = {'query':domain}

        return self.do_post(payload=payload, endpoint='/v1/domain/lite/scan')


    def domain_quick_view(self, domain):
        """
        This is an API for checking if a specific URL is connected to a legitimate website or a malicious website.
It can be used to classify websites as either malicious or legitimate.


        """

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/hash/view', params=params)


    def domain_quick_mal_view(self, domain):
        """
        This is an API for checking if a specific URL is connected to a malicious website.
It is recommended to use only to verify whether a website is malicious or not.
        """

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/malicious/view', params=params)


    def domain_quick_trusted_view(self, domain):
        """
        This is an API for checking if a specific URL is connected to a legitimate website.
It is recommended to use only to verify whether a website is legitimate or not.
        """

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/trusted/view', params=params)



    def exploit_search(self, query, offset):
        """
        API for retrieving information on a specific CVE vulnerability.
        """

        final_result = {}

        for iter in range(0, offset, 10):

            params = {
                'query': query,
                'offset': iter
            }

            results = self.do_get(endpoint='/v1/exploit/search', params=params)

            if not results or int(results.get('status')) != 200:
                break
            
            final_result.update(results)

        return final_result



    def feed_status(self, key):
        """
        Query the current status (creation time, number of data, availability, and stale status) of 4 types of TI Feeds. A valid license key is required.
        """

        params = {'key':key}

        return self.do_get(endpoint='/ti/v1/feed/status', params=params)



    # /ti/v1/feed/{direction} will be implemented in the future.


    