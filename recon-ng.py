#!/usr/bin/python -tt

import sys
import re
import time
import random
import json
import urllib
import urllib2
import optparse
import socket
import os
import httplib2
import urlparse
import oauth2 as oauth

print """
    _/_/_/    _/_/_/_/    _/_/_/    _/_/    _/      _/              _/      _/    _/_/_/   
   _/    _/  _/        _/        _/    _/  _/_/    _/              _/_/    _/  _/          
  _/_/_/    _/_/_/    _/        _/    _/  _/  _/  _/  _/_/_/_/_/  _/  _/  _/  _/  _/_/     
 _/    _/  _/        _/        _/    _/  _/    _/_/              _/    _/_/  _/    _/      
_/    _/  _/_/_/_/    _/_/_/    _/_/    _/      _/              _/      _/    _/_/_/       
"""

#=================================================
# MAIN FUNCTION
#=================================================

def main():
    import optparse
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog
    epilog = """
    Contact Mutation Options:
    --mutate 1            => johndoe
    --mutate 2            => john.doe
    --mutate 3            => jdoe
    --mutate 4            => j.doe
    --mutate \'<fi>.<ln>\'  => j.doe
      Pattern options: <fi>,<fn>,<li>,<ln>
      Example \'<fi>.<ln>@domain.com\' => \'j.doe@domain.com\'\n\n"""
    usage = '%prog [mode] [options]'
    desc = '%prog - Tim Tomes (@LaNMaSteR53) (www.lanmaster53.com)'
    parser = optparse.OptionParser(usage=usage, epilog=epilog, description=desc)
    parser.add_option('-v', help='enable verbose mode', dest='verbose', default=False, action='store_true')
    parser.add_option('-o', metavar='filename', help='output to a csv file (append)', dest='filename', type='string', action='store')
    parser.add_option('-d', metavar='domain', help='enumerate domain hosts (Host Enumeration Mode)', dest='domain', type='string', action='store')
    parser.add_option('-c', metavar='"company"|domain', help='enumerate company contacts (Contact Enumeration Mode)', dest='company', type='string', action='store')
    parser.add_option('--all', help='enable all harvesting modules per mode selected', dest='all', default=False, action='store_true')
    group1 = optparse.OptionGroup(parser, 'Host Enumeration Mode (-d)')
    group1.add_option('--gxfr', help='enable GXFR module', dest='gxfr', default=False, action='store_true')
    group1.add_option('--bxfr', help='enable BXFR module', dest='bxfr', default=False, action='store_true')
    group1.add_option('--yxfr', help='enable YXFR module', dest='yxfr', default=False, action='store_true')
    group1.add_option('--shodan', help='enable Shodan module', dest='shodan', default=False, action='store_true')
    group1.add_option('--resolve', help='resolve enumerated hostnames to IP address', dest='resolve', default=False, action='store_true')
    group2 = optparse.OptionGroup(parser, 'Contact Enumeration Mode (-c)')
    group2.add_option('-k', metavar='"key words"', help='additional search terms for company', default='', dest='key_words', type='string', action='store')
    group2.add_option('--jigsaw', help='enable Jigsaw module', dest='jigsaw', default=False, action='store_true')
    group2.add_option('--linkedin', help='enable LinkedIn module', dest='linkedin', default=False, action='store_true')
    group2.add_option('--linkedin-auth', help='enable LinkedIn w/Authentication module', dest='linkedin_auth', default=False, action='store_true')
    group2.add_option('--mutate', metavar="type", help='mutate contacts to create usernames or email addresses', default='', dest='mutate', type='string', action='store')
    parser.add_option_group(group1)
    parser.add_option_group(group2)
    (opts, args) = parser.parse_args()
    # at least one module required to run
    if not opts.domain and not opts.company:
        parser.error("[!] Must Enumerate Something.")
    verbose = False
    if opts.verbose: verbose = opts.verbose

    # harvest target employees
    contacts = []
    if opts.company:
        print '[-] Enumerating Contacts For: %s...' % (opts.company)
        if opts.jigsaw or opts.all:
            print '===== Jigsaw ====='
            j = jigsaw(opts.company, opts.key_words)
            j.verbose = verbose
            company_id = j.get_company_id()
            if company_id:
                contacts.extend(j.get_contacts(company_id))
        if opts.linkedin or opts.all:
            print '===== LinkedIn ====='
            l = linkedin(opts.company, opts.key_words)
            l.verbose = verbose
            contacts.extend(l.get_contacts())
        if opts.linkedin_auth or opts.all:
            print '===== LinkedIn (Authenticated) ====='
            la = linkedin_auth(opts.company, opts.key_words)
            la.verbose = verbose
            contacts.extend(la.get_contacts())
        # display harvested contacts and write to file
        if contacts:
            contacts = list(set(contacts))
            if opts.mutate: contacts = mutate_contacts(contacts, opts.mutate)
            print '[!] Total Contacts Harvested: %d' % len(contacts)
            if opts.filename: append_to_outfile(contacts, opts.filename)
        else:
            print '[!] No Contacts Harvested!'

    # harvest target hosts
    hosts = []
    if opts.domain:
        print '[-] Enumerating Hosts For: %s...' % (opts.domain)
        if opts.gxfr or opts.all:
            print '===== GXFR ====='
            g = gxfr(opts.domain)
            g.verbose = verbose
            hosts.extend(g.get_subs_via_web())
        if opts.bxfr or opts.all:
            print '===== BXFR ====='
            b = bxfr(opts.domain)
            b.verbose = verbose
            hosts.extend(b.get_subs_via_web())
        if opts.yxfr or opts.all:
            print '===== YXFR ====='
            y = yxfr(opts.domain)
            y.verbose = verbose
            hosts.extend(y.get_subs_via_web())
        if opts.shodan or opts.all:
            print '===== Shodan ====='
            s = shodan(opts.domain)
            s.verbose = verbose
            hosts.extend(s.get_subs_via_api())
        if hosts:
            hosts = list(set(['%s.%s' % (host, opts.domain) for host in hosts]))
            if opts.resolve: hosts = resolve_hosts(hosts, opts.domain)
            print '[!] Total Hosts Harvested: %d' % len(hosts)
            if opts.filename: append_to_outfile(hosts, opts.filename)
        else:
            print '[!] No Hosts Harvested!'

#=================================================
# HOST ENUMERATION CLASS DECLARATIONS
#=================================================

class base_hosts(object):

    def __init__(self, domain):
        self.verbose = False
        self.user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
        self.domain = domain

class shodan(base_hosts):

    def __init__(self, domain):
        base_hosts.__init__(self, domain)

    def get_subs_via_api(self):
        subs = []
        key = get_key('shodan')
        if not key:
            print '[!] No API Key. Skipping Module.'
            return subs
        base_url = 'http://www.shodanhq.com/api/search'
        params = 'q=hostname:%s&key=%s' % (self.domain, key)
        url = '%s?%s' % (base_url, params)
        page = 1
        # loop until no results are returned
        while True:
            new = False
            # build and send request
            request = urllib2.Request(url)
            request.add_header('User-Agent', self.user_agent)
            #handler = urllib2.HTTPHandler(debuglevel=1)
            requestor = urllib2.build_opener()
            content = None
            try: content = requestor.open(request)
            except KeyboardInterrupt: pass
            except Exception as e:
                print '[!] Error: %s.' % (str(e))
            if not content: break
            content = content.read()
            jsonobj = json.loads(content)
            try: results = jsonobj['matches']
            except KeyError: break
            for result in results:
                hostnames = result['hostnames']
                for hostname in hostnames:
                    sub = '.'.join(hostname.split('.')[:-2])
                    if sub and not sub in subs:
                        print '[Host] %s.%s' % (sub, self.domain)
                        subs.append(sub)
                        new = True
            #break # large results will exhaust API query pool. Use this to restrict to one page.
            if not new: break
            page += 1
            url = '%s?%s&page=%s' % (base_url, params, str(page))
        return subs

# Google
class gxfr(base_hosts):

    def __init__(self, domain):
        base_hosts.__init__(self, domain)

    def get_subs_via_web(self):
        base_url = 'https://www.google.com'
        base_uri = '/search?'
        base_query = 'site:' + self.domain
        pattern = '<a\shref="\w+://(\S+?)\.%s\S+?"\sclass=l'  % (self.domain) #'<cite>(?:https*://)*(\S+?)\.%s.+?</cite>'
        subs = []
        # control variables
        new = True
        page = 0
        nr = 10
        # execute search engine queries and scrape results storing subdomains in a list
        # loop until no new subdomains are found
        while new == True:
            content = None
            query = ''
            # build query based on results of previous results
            for sub in subs:
                query += ' -site:%s.%s' % (sub, self.domain)
            full_query = base_query + query
            start_param = 'start=%d' % (page*nr)
            query_param = 'q=%s' % (urllib.quote_plus(full_query))
            if len(base_uri) + len(query_param) + 1 + len(start_param) < 2048:
                last_query_param = query_param
                params = '%s&%s' % (query_param, start_param)
            else:
                params = last_query_param[:2047-len(start_param)-len(base_uri)] + start_param
            full_url = base_url + base_uri + params
            # note: query character limit is passive in mobile, but seems to be ~794
            # note: query character limit seems to be 852 for desktop queries
            # note: typical URI max length is 2048 (starts after top level domain)
            if self.verbose: print '[URL] %s' % full_url
            # build and send request
            request = urllib2.Request(full_url)
            request.add_header('User-Agent', self.user_agent)
            requestor = urllib2.build_opener()
            # send query to search engine
            try: content = requestor.open(request)
            except KeyboardInterrupt: pass
            except Exception as e:
                if '503' in str(e):
                    print '[!] Possible Shun: Use --proxy or find something else to do for 24 hours. ;_;'
                elif self.verbose:
                    print '[!] %s. Returning Previously Harvested Results.' % str(e)
            if not content: break
            content = content.read()
            sites = re.findall(pattern, content)
            # create a uniq list
            sites = list(set(sites))
            new = False
            # add subdomain to list if not already exists
            for site in sites:
                if site not in subs:
                    print '[Host] %s.%s' % (site, self.domain)
                    subs.append(site)
                    new = True
            # exit if maximum number of queries has been made
            # start going through all pages if query size is maxed out
            if not new:
                # exit if all subdomains have been found
                if not '>Next</span>' in content:
                    break
                else:
                    page += 1
                    if self.verbose: print '[-] No New Subdomains Found on the Current Page. Jumping to Result %d.' % ((page*nr)+1)
                    new = True
            # sleep script to avoid lock-out
            if self.verbose: print '[-] Sleeping to Avoid Lock-out...'
            try: time.sleep(random.randint(5,15))
            except KeyboardInterrupt: break
        # print list of subdomains
        if self.verbose: print '[-] Final Query String: %s' % (full_url)
        return subs

# Bing
class bxfr(base_hosts):

    def __init__(self, domain):
        base_hosts.__init__(self, domain)

    def get_subs_via_web(self):
        base_url = 'http://www.bing.com'
        base_uri = '/search?'
        base_query = 'site:' + self.domain
        pattern = '"sb_tlst"><h3><a href="\w+://(\S+?)\.%s' % (self.domain)
        subs = []
        # control variables
        new = True
        page = 0
        nr = 50
        # execute search engine queries and scrape results storing subdomains in a list
        # loop until no new subdomains are found
        while new == True:
            content = None
            query = ''
            # build query based on results of previous results
            for sub in subs:
                query += ' -site:%s.%s' % (sub, self.domain)
            full_query = base_query + query
            start_param = 'first=%s' % (str(page*nr))
            query_param = 'q=%s' % (urllib.quote_plus(full_query))
            params = '%s&%s' % (query_param, start_param)
            full_url = base_url + base_uri + params
            # note: typical URI max length is 2048 (starts after top level domain)
            if self.verbose: print '[URL] %s' % full_url
            # build and send request
            request = urllib2.Request(full_url)
            request.add_header('User-Agent', self.user_agent)
            request.add_header('Cookie', 'SRCHHPGUSR=NEWWND=0&NRSLT=%d&SRCHLANG=&AS=1;' % (nr))
            requestor = urllib2.build_opener()
            # send query to search engine
            try: content = requestor.open(request)
            except KeyboardInterrupt: pass
            except Exception as e: print '[!] %s. Returning Previously Harvested Results.' % str(e)
            if not content: break
            content = content.read()
            sites = re.findall(pattern, content)
            # create a uniq list
            sites = list(set(sites))
            new = False
            # add subdomain to list if not already exists
            for site in sites:
                if site not in subs:
                    print '[Host] %s.%s' % (site, self.domain)
                    subs.append(site)
                    new = True
            # exit if maximum number of queries has been made
            # start going through all pages if query size is maxed out
            if not new:
                # exit if all subdomains have been found
                if not '>Next</a>' in content:
                    # curl to stdin breaks pdb
                    break
                else:
                    page += 1
                    if self.verbose: print '[-] No New Subdomains Found on the Current Page. Jumping to Result %d.' % ((page*nr)+1)
                    new = True
            # sleep script to avoid lock-out
            if self.verbose: print '[-] Sleeping to Avoid Lock-out...'
            try: time.sleep(random.randint(5,15))
            except KeyboardInterrupt: break
        # print list of subdomains
        if self.verbose: print '[-] Final Query String: %s' % (full_url)
        return subs

# Yahoo
class yxfr(base_hosts):

    def __init__(self, domain):
        base_hosts.__init__(self, domain)

    def get_subs_via_web(self):
        base_url = 'http://search.yahoo.com'
        base_uri = '/search?'
        base_query = 'site:' + self.domain
        pattern = 'url>(?:<b>)*(\S+?)\.(?:<b>)*%s</b>' % (self.domain)
        #pattern = '\*\*http%%3a//(\S*)\.%s/' % (self.domain)
        subs = []
        # control variables
        new = True
        page = 0
        nr = 100
        # execute search engine queries and scrape results storing subdomains in a list
        # loop until no new subdomains are found
        while new == True:
            content = None
            query = ''
            # build query based on results of previous results
            for sub in subs:
                query += ' -site:%s.%s' % (sub, self.domain)
            full_query = base_query + query
            num_param = 'n=%d' % (nr)
            start_param = 'b=%s' % (str(page*nr))
            query_param = 'p=%s' % (urllib.quote_plus(full_query))
            params = '%s&%s&%s' % (num_param, query_param, start_param)
            full_url = base_url + base_uri + params
            # note: typical URI max length is 2048 (starts after top level domain)
            if self.verbose: print '[URL] %s' % full_url
            # build and send request
            request = urllib2.Request(full_url)
            request.add_header('User-Agent', self.user_agent)
            requestor = urllib2.build_opener()
            # send query to search engine
            try: content = requestor.open(request)
            except KeyboardInterrupt: pass
            except Exception as e: print '[!] %s. Returning Previously Harvested Results.' % str(e)
            if not content: break
            content = content.read()
            sites = re.findall(pattern, content)
            # create a uniq list
            sites = list(set(sites))
            new = False
            # add subdomain to list if not already exists
            for site in sites:
                # remove left over bold tags remaining after regex
                site = site.replace('<b>', '')
                site = site.replace('</b>', '')
                if site not in subs:
                    print '[Host] %s.%s' % (site, self.domain)
                    subs.append(site)
                    new = True
            # exit if maximum number of queries has been made
            # start going through all pages if query size is maxed out
            if not new:
                # exit if all subdomains have been found
                if not 'Next &gt;</a>' in content:
                    # curl to stdin breaks pdb
                    break
                else:
                    page += 1
                    if self.verbose: print '[-] No New Subdomains Found on the Current Page. Jumping to Result %d.' % ((page*nr)+1)
                    new = True
            # sleep script to avoid lock-out
            if self.verbose: print '[-] Sleeping to Avoid Lock-out...'
            try: time.sleep(random.randint(5,15))
            except KeyboardInterrupt: break
        # print list of subdomains
        if self.verbose: print '[-] Final Query String: %s' % (full_url)
        return subs

#=================================================
# CONTACT ENUMERATION CLASS DECLARATIONS
#=================================================

class base_contacts(object):

    def __init__(self, company, key_words):
        self.verbose = False
        self.company = company
        self.key_words = key_words

class jigsaw(base_contacts):

    def __init__(self, company, key_words=''):
        base_contacts.__init__(self, company, key_words)

    def get_company_id(self):
        print '[-] Searching Jigsaw CRM for Employees of \'%s\'...' % self.company
        all_companies = []
        page_cnt = 1
        params = '%s %s' % (self.company, self.key_words)
        base_url = 'http://www.jigsaw.com/FreeTextSearchCompany.xhtml?opCode=search&freeText=%s' % (urllib.quote_plus(params))
        url = base_url
        while True:
            if self.verbose: print '[Query] %s' % url
            try:
                content = urllib.urlopen(url).read()
            except KeyboardInterrupt:
                break
            pattern = "href=./id(\d+?)/.+?>(.+?)<.+?\n.+?title='([\d,]+?)'"
            companies = re.findall(pattern, content)
            if not companies:
                if content.find('did not match any results') == -1 and page_cnt == 1:
                    pattern_id = '<a href="/id(\d+?)/.+?">'
                    pattern_name = 'pageTitle.>(.+?)<'
                    pattern_cnt = 'contactCount.+>\s+(\d+)\sContacts'
                    if content.find('Create a wiki') != -1:
                        pattern_id = '<a href="/.+?companyId=(\d+?)">'
                    company_id = re.findall(pattern_id, content)[0]
                    company_name = re.findall(pattern_name, content)[0]
                    contact_cnt = re.findall(pattern_cnt, content)[0]
                    all_companies.append((company_id, self.company, contact_cnt))
                break
            for company in companies:
                all_companies.append((company[0], company[1], company[2]))
            page_cnt += 1
            url = base_url + '&rpage=%d' % (page_cnt)
        if len(all_companies) == 0:
            print '[-] No Company Matches Found.'
            return False
        else:
            print 'Company ID'.ljust(15) + 'Company Name'.ljust(55) + 'Contacts'
            print '=========='.ljust(15) + '============'.ljust(55) + '========'
            for company in all_companies:
                print company[0].ljust(15) + company[1].ljust(55) + company[2]
            if len(all_companies) > 1:
                print '[-] Possible Company Matches Found: %d' % len(all_companies)
                try: company_id = raw_input('[+] Enter Company ID from list [%s]: ' % (all_companies[0][0]))
                except KeyboardInterrupt: company_id = ''
                if not company_id: company_id = all_companies[0][0]
            else:
                company_id = all_companies[0][0]
                print '[-] Unique Company Match Found: %s' % company_id
            return company_id

    def get_contacts(self, company_id):
        print '[-] Searching Company ID %s for contacts...' % company_id
        all_contacts = []
        page_cnt = 1
        base_url = 'http://www.jigsaw.com/SearchContact.xhtml?companyId=%s&opCode=showCompDir' % (company_id)
        url = base_url
        while True:
            url = base_url + '&rpage=%d' % (page_cnt)
            if self.verbose: print '[Query] %s' % url
            try:
                content = urllib.urlopen(url).read()
            except KeyboardInterrupt:
                break
            pattern = "<span.+?>(.+?)</span>.+?\n.+?href.+?\('(\d+?)'\)>(.+?)<"
            contacts = re.findall(pattern, content)
            if not contacts: break
            for contact in contacts:
                title = contact[0]
                contact_id = contact[1]
                if contact[2].find('...') != -1:
                    url = 'http://www.jigsaw.com/BC.xhtml?contactId=%s' % contact_id
                    try:
                        content = urllib.urlopen(url).read()
                    except KeyboardInterrupt:
                        break
                    pattern = '<span id="firstname">(.+?)</span>.*?<span id="lastname">(.+?)</span>'
                    names = re.findall(pattern, content)
                    fname = unescape(names[0][0])
                    lname = unescape(names[0][1])
                else:
                    fname = unescape(contact[2].split(',')[1].strip())
                    lname = unescape(contact[2].split(',')[0].strip())
                all_contacts.append((fname, lname, title))
                print '[Contact] %s %s - %s' % (fname, lname, title)
            page_cnt += 1
        return all_contacts

class linkedin_auth(base_contacts):

    def __init__(self, company, key_words=''):
        base_contacts.__init__(self, company, key_words)
        consumer_key = get_key('linkedin_key', 'LinkedIn API Key')
        consumer_secret = get_key('linkedin_secret', 'LinkedIn Secret Key')
        if not consumer_key or not consumer_secret: print '[!] Warning. Blank keys will result in inaccurate data.'
        # Use API key and secret to instantiate consumer object
        self.consumer = oauth.Consumer(consumer_key, consumer_secret)
        self.access_token = {'oauth_token': get_token('linkedin_token'),'oauth_token_secret': get_token('linkedin_token_secret')}
        if not self.access_token['oauth_token']: self.get_access_tokens()

    def get_access_tokens(self):
        client = oauth.Client(self.consumer)
        request_token_url = 'https://api.linkedin.com/uas/oauth/requestToken'
        resp, content = client.request(request_token_url, "POST")
        if resp['status'] != '200':
            raise Exception("[!] Error: Invalid Response %s." % resp['status'])
        request_token = dict(urlparse.parse_qsl(content))
        authorize_url = 'https://api.linkedin.com/uas/oauth/authorize'
        print "Go to the following link in your browser and enter the pin below:"
        print "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])
        oauth_verifier = raw_input('Enter PIN: ')
        access_token_url = 'https://api.linkedin.com/uas/oauth/accessToken'
        token = oauth.Token(request_token['oauth_token'], request_token['oauth_token_secret'])
        token.set_verifier(oauth_verifier)
        client = oauth.Client(self.consumer, token)
        resp, content = client.request(access_token_url, "POST")
        self.access_token = dict(urlparse.parse_qsl(content))
        add_token('linkedin_token', self.access_token['oauth_token'])
        add_token('linkedin_token_secret', self.access_token['oauth_token_secret'])
    
    def get_contacts(self):
        print '[-] Searching LinkedIn (Authenticated) for Employees of \'%s\'...' % self.company
        # Use developer token and secret to instantiate access token object
        contacts = []
        token = oauth.Token(key=get_key('linkedin_token'), secret=get_key('linkedin_token_secret'))
        client = oauth.Client(self.consumer, token)
        count = 25
        base_url = "http://api.linkedin.com/v1/people-search:(people:(id,first-name,last-name,headline))?format=json&company-name=%s&current-company=true&count=%d" % (urllib.quote_plus(self.company), count)
        url = base_url
        page = 1
        while True:
            # Make call to LinkedIn to retrieve your own profile
            resp,content = client.request(url)
            if resp['status'] == '401':
                print '[!] Access Token Needed or Expired.'
                self.get_access_tokens()
                contacts = self.get_contacts()
                break
            try: jsonobj = json.loads(content)
            except ValueError as e:
                print '[!] Error: %s in %s' % (e, url)
                continue
            if not 'values' in jsonobj['people']: break
            for contact in jsonobj['people']['values']:
                if 'headline' in contact:
                    title = sanitize(contact['headline'])
                    fname = sanitize(unescape(re.split('[\s]',contact['firstName'])[0]))
                    lname = sanitize(unescape(re.split('[,;]',contact['lastName'])[0]))
                    print '[Contact] %s %s - %s' % (fname, lname, title)
                    contacts.append((fname, lname, title))
            if not '_start' in jsonobj['people']: break
            if jsonobj['people']['_start'] + jsonobj['people']['_count'] == jsonobj['people']['_total']: break
            start = page * jsonobj['people']['_count']
            url = '%s&start=%d' % (base_url, start)
            page += 1
        return contacts

class linkedin(base_contacts):

    def __init__(self, company, key_words=''):
        base_contacts.__init__(self, company, key_words)
        self.user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'

    def get_contacts(self):
        print '[-] Searching LinkedIn for Employees of \'%s\'...' % self.company
        base_url = 'https://www.google.com/search?'
        pattern = '<a\shref="(\S+?)"\sclass=l'
        contacts = []
        #base_queries = ['site:www.linkedin.com']
        base_queries = ['site:www.linkedin.com/in','site:www.linkedin.com/pub']
        for base_query in base_queries:
            full_query = '%s "at %s" %s' % (base_query, self.company, self.key_words)
            if self.verbose: print '[Query] %s' % full_query
            page = 0
            nr = 10
            while True:
                content = ''
                query = urllib.urlencode({'q':full_query, 'start':page*nr})
                url = '%s%s' % (base_url, query)
                if self.verbose: print '[URL] %s' % (url)
                request = urllib2.Request(url)
                request.add_header('User-agent', self.user_agent)
                requestor = urllib2.build_opener()
                try: response = requestor.open(request)
                except KeyboardInterrupt: return contacts
                except Exception as e:
                    print '[!] Error: %s.' % (e)
                    continue
                content = response.read()
                results = re.findall(pattern, content)
                for result in results:
                    if self.verbose: print '[Result] %s' % result
                    try: contact = self.validate_employment(result)
                    except KeyboardInterrupt: return contacts
                    if contact: contacts.append(contact)
                if not '>Next</span>' in content: break
                page += 1
                if self.verbose: print '[-] Sleeping to Avoid Lock-out...'
                try: time.sleep(random.randint(5,15))
                except KeyboardInterrupt: return contacts
        return contacts

    def validate_employment(self, link):
        url = link.lower()
        i = 0
        content = ''
        contact, fname, lname, title = None, None, None, None
        try: content = urllib.urlopen(url).read().split('\n')
        except IOError as e:
            print '[!] Error: %s' % (e)
        for line in content:
            # get the first and last names
            if 'class="full-name"' in line:
                m = re.search('given-name">(.+?)<.+family-name">(.+?)<', line)
                fname = sanitize(unescape(re.split('[\s]',m.group(1))[0]))
                lname = sanitize(unescape(re.split('[,;]',m.group(2))[0]))
            # get current job title
            elif 'headline-title title' in line:
                job = unescape(content[i+1])
                # if current job is named company
                if self.company.lower() in job.lower():
                    title = job.strip()
            if fname and lname and title:
                contact = (fname, lname, title)
                #print '[Profile] %s' % link
                print '[Contact] %s %s - %s' % (fname, lname, title)
                break
            i += 1
        return contact

#=================================================
# SUPPORT FUNCTIONS
#=================================================

def mutate_contacts(contacts, type):
    print '[-] Mutating Contacts...'
    new_contacts = []
    for contact in contacts:
        if type == '1':
            #johndoe
            permutation = contact[0].lower() + contact[1].lower()
        elif type == '2':
            #john.doe
            permutation = contact[0].lower() + '.' + contact[1].lower()
        elif type == '3':
            #jdoe
            permutation = contact[0][:1].lower() + contact[1].lower()
        elif type == '4':
            #j.doe
            permutation = contact[0][:1].lower() + '.' + contact[1].lower()
        else:
            permutation = type
            try:
                fn = contact[0].lower()
                fi = contact[0][:1].lower()
                ln = contact[1].lower()
                li = contact[1][:1].lower()
                permutation = permutation.replace('<fn>', fn)
                permutation = permutation.replace('<fi>', fi)
                permutation = permutation.replace('<ln>', ln)
                permutation = permutation.replace('<li>', li)
            except:
                print '[!] Invalid Mutation Pattern \'%s\'.' % (type)
                break
        print '[Mutation] %s' % (permutation)
        new_contacts.append((contact[0], contact[1], permutation, contact[2]))
    return new_contacts

def resolve_hosts(hosts, domain):
    print '[-] Resolving Hostnames to IP...'
    new_hosts = []
    # create a list of all associated ips to the subdomain
    for host in hosts:
        # dns query and dictionary assignment
        try: ips = list(set([item[4][0] for item in socket.getaddrinfo(host, 80)]))
        except socket.gaierror: ips = ['no entry']
        for ip in ips:
            print '[Address] %s - %s' % (ip, host)
            new_hosts.append((host,ip))
    return new_hosts

def append_to_outfile(items, outfilename):
    outfile = open(outfilename, 'ab')
    for item in items:
        if type(item) == str or type(item) == unicode:
            outfile.write('%s\n' % (item))
        else:
            import csv
            csvwriter = csv.writer(outfile, quoting=csv.QUOTE_ALL)
            csvwriter.writerow(item)
    outfile.close()
    print '[+] %d Items Added to \'%s\'.' % (len(items), outfilename)

def get_key(key_name, key_text='API Key'):
    keyfile = 'api.keys'
    if os.path.exists(keyfile):
        for line in open(keyfile):
            key, value = line.split('::')[0], line.split('::')[1]
            if key == key_name:
                return value.strip()
    try: key = raw_input("Enter %s (blank to skip): " % (key_text))
    except KeyboardInterrupt: return ''
    if key:
        file = open(keyfile, 'a')
        file.write('%s::%s\n' % (key_name, key))
        file.close()
    return key

def get_token(key_name):
    keyfile = 'api.keys'
    if os.path.exists(keyfile):
        for line in open(keyfile):
            key, value = line.split('::')[0], line.split('::')[1]
            if key == key_name:
                return value.strip()
    return ''

def add_token(key_name, key_value):
    keys = []
    keyfile = 'api.keys'
    if os.path.exists(keyfile):
        # remove the old key if duplicate
        for line in open(keyfile):
            key = line.split('::')[0]
            if key != key_name:
                keys.append(line)
    keys = ''.join(keys)
    file = open(keyfile, 'w')
    file.write(keys)
    file.write('%s::%s\n' % (key_name, key_value))
    file.close()

def unescape(s):
    import htmllib
    p = htmllib.HTMLParser(None)
    p.save_bgn()
    p.feed(s)
    return p.save_end()

def sanitize(item):
    return ''.join([char for char in item if ord(char) >= 32 and ord(char) <= 126])

#=================================================
# START
#=================================================

if __name__ == "__main__": main()
