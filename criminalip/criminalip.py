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

        params={'ip':ip_address}

        return self.do_get(endpoint="v1/ip/vpn", params=params)


    def ip_hosting(self, ip_address, full=False):

            params={'ip':ip_address,
                    'full': full}

            return self.do_get(endpoint='v1/ip/hosting', params=params)


    def ip_mal_info(self, ip_address):

        params = {'ip':ip_address}

        return self.do_get(endpoint='v2/feature/ip/malicious-info', params=params)


    def ip_privacy_threats(self, ip_address):

        params = {'ip':ip_address}

        return self.do_get(endpoint='v1/feature/ip/privacy-threat', params=params)


    def is_safe_dns_server(self, ip_address):

        params = {'ip':ip_address}

        return self.do_get(endpoint='v1/feature/ip/is_safe_dns_server', params=params)


    def ip_suspicious_info(self, ip_address):

        params = {'ip':ip_address}

        return self.do_get(endpoint='v2/feature/ip/suspicious-info', params=params)


    def banner_search(self, query, offset):

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

        params = {'query':query}

        return self.do_get(endpoint='/v1/banner/stats', params=params)


    def domain_reports(self, query, offset):

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
        

        return self.do_get(endpoint=f'v1/domain/reports/{id}')



    def get_domain_status_by_id(self, id):

        return self.do_get(endpoint=f'/v1/domain/status/{id}')



    def domain_scan(self, domain):

        payload = {'query':domain}

        return self.do_post(payload=payload, endpoint='/v1/domain/scan')



    def domain_scan(self, domain):
    
            payload = {'query':domain}
    
            return self.do_post(payload=payload, endpoint='/v1/domain/scan/private')


    def domain_lite_report(self, query, offset):

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

        params = {'scan_id':scan_id}

        return self.do_get(endpoint='/v1/domain/lite/progress', params=params)



    def domain_lite_report_by_id(self, scan_id):

        return self.do_get(endpoint=f'/v1/domain/lite/report/{scan_id}')


    def domain_lite_scan(self, domain):

        payload = {'query':domain}

        return self.do_post(payload=payload, endpoint='/v1/domain/lite/scan')


    def domain_quick_view(self, domain):

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/hash/view', params=params)


    def domain_quick_mal_view(self, domain):

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/malicious/view', params=params)


    def domain_quick_trusted_view(self, domain):

        params = {'domain':domain}

        return self.do_get(endpoint='/v1/domain/quick/trusted/view', params=params)



    def exploit_search(self, query, offset):

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

        params = {'key':key}

        return self.do_get(endpoint='/ti/v1/feed/status', params=params)



    # /ti/v1/feed/{direction} will be implemented in the future.


    