#!/usr/bin/python3
import mailbox
from email.message import EmailMessage
from email.parser import BytesParser, Parser
from email.policy import default
from urllib.parse import urlparse
from typing import List
import os
import re

'''
References:
https://docs.python.org/3/library/mailbox.html
https://docs.python.org/3/library/mailbox.html#mailbox.mboxMessage
https://docs.python.org/3/library/urllib.parse.html
https://docs.python.org/3/library/email.message.html#email.message.EmailMessage
'''

class URLFeatures:
    def __init__(self, url: str, phishiness: bool = False) -> None:
        self.url = url
        self.domain = None # TODO
        self.path = None # TODO
        self.parameters = None # TODO
        self.link_text = None
        self.from_domain = None
        self.phishiness = phishiness
        # Context attributes
        self.domain_matches_from_degree = None
        self.tld_plus_1_matches = None
        self.domain_is_subdomain_of_from = None
        self.from_is_subdomain_of_domain = None

        self.link_text_contains_url = None
        self.url_matches_link_text = None
        self.url_domain_matches_link_text_domain = None
        # URL attributes
        self.periods_present_count = 0
        self.at_symbol_before_domain = None
        self.url_length = None
        self.domain_length = None
        self.domain_part_count = None
        self.path_length = None
        self.parameters_length = None
        return

    def __repr__(self) -> str:
        repr = ""
        repr += "URL: {}\n".format(self.url)
        repr += "\tPhishiness:   {}\n".format(self.phishiness)
        repr += "\tDomain:       {}\n".format(self.domain)
        repr += "\tFrom domain:  {}\n".format(self.from_domain)
        repr += "\tLink text:    {}\n".format(self.link_text)
        repr += "\tPath:         {}\n".format(self.path)
        repr += "\tParams:       {}\n".format(self.parameters)
        repr += "\tFeatures\n"
        repr += "\t\tPhishiness:                          {}\n".format(self.phishiness)
        repr += "\t\tDomain matches from degree:          {}\n".format(self.domain_matches_from_degree)
        repr += "\t\tTLD+1 Matches:                       {}\n".format(self.tld_plus_1_matches)
        repr += "\t\tdomain_is_subdomain_of_from:         {}\n".format(self.domain_is_subdomain_of_from)
        repr += "\t\tfrom_is_subdomain_of_domain:         {}\n".format(self.from_is_subdomain_of_domain)

        repr += "\t\tLink Text Contains URL:              {}\n".format(self.link_text_contains_url)
        repr += "\t\tURL matches link Text:               {}\n".format(self.url_matches_link_text)
        repr += "\t\tURL domain matches link text domain: {}\n".format(self.url_domain_matches_link_text_domain)

        repr += "\t\tPeriods present:                     {}\n".format(self.periods_present_count)
        repr += "\t\tAt symbol before domain:             {}\n".format(self.at_symbol_before_domain)
        repr += "\t\tURL length:                          {}\n".format(self.url_length)
        repr += "\t\tDomain length:                       {}\n".format(self.domain_length)
        repr += "\t\tDomain part count:                   {}\n".format(self.domain_part_count)
        repr += "\t\tPath length:                         {}\n".format(self.path_length)
        repr += "\t\tParameters length:                   {}\n".format(self.parameters_length)
        return repr

    def toMachineLearningCSV(self) -> str:
        repr = ""
        repr += "{},".format(self.phishiness)
        repr += "{},".format(self.domain_matches_from_degree)
        repr += "{},".format(self.tld_plus_1_matches)
        repr += "{},".format(self.domain_is_subdomain_of_from)
        repr += "{},".format(self.from_is_subdomain_of_domain)

        repr += "{},".format(self.link_text_contains_url)
        repr += "{},".format(self.url_matches_link_text)
        repr += "{},".format(self.url_domain_matches_link_text_domain)

        repr += "{},".format(self.periods_present_count)
        repr += "{},".format(self.at_symbol_before_domain)
        repr += "{},".format(self.url_length)
        repr += "{},".format(self.domain_length)
        repr += "{},".format(self.domain_part_count)
        repr += "{},".format(self.path_length)
        repr += "{}".format(self.parameters_length)
        return repr


    @staticmethod
    def compareDomains(domainA: List[str], domainB: List[str]):

        domain_matches_from_degree = 0;
        tld_plus_1_matches = False
        domainA_is_subdomain_of_domainB = False
        domainB_is_subdomain_of_domainA = False

        # Check for match
        for i in range(0, max(len(domainA), len(domainB)) - 1):
            if (i < len(domainA) and i < len(domainB)):
                # Both are available
                # Things to compare
                # print("domain_matches_from_degree comparing: {} == {}".format(domainA[-i -1], domainB[-i -1])) # TODO: Remove print
                if (domainA[-i -1] == domainB[-i -1]):
                    domain_matches_from_degree += 1

        tld_plus_1_matches = True if domain_matches_from_degree >= 2 else False
        domainA_is_subdomain_of_domainB = True if domain_matches_from_degree == len(domainA) else False
        domainB_is_subdomain_of_domainA = True if domain_matches_from_degree == len(domainB) else False
        return (domain_matches_from_degree, tld_plus_1_matches, domainA_is_subdomain_of_domainB, domainB_is_subdomain_of_domainA)

    def extractFeatures(self) -> None:
        # Extract URL attributes
        results = urlparse(self.url)
        self.domain = results.hostname
        self.path = results.path
        self.parameters = results.params
        self.periods_present_count = self.url.count('.')
        self.at_symbol_before_domain = results.netloc.count('@') > 0
        self.url_length = len(self.url)
        self.domain_length = len(self.domain)
        self.path_length = len(self.path)
        self.parameters_length = len(self.parameters)

        # Check the domain
        domain_split = self.domain.split(".")
        self.domain_part_count = len(domain_split)

        # Extract the context dependent attributes, if they are available
        # Extract and evaluate using the from domain
        if (self.from_domain != None):
            from_split = self.from_domain.split(".")
            # Examine domain in context of from
            results = URLFeatures.compareDomains(domain_split, from_split)
            self.domain_matches_from_degree = results[0]
            self.tld_plus_1_matches = results[1]
            self.domain_is_subdomain_of_from = results[2]
            self.from_is_subdomain_of_domain = results[3]
            self.from_part_count = len(from_split)
        # Extract and evaluate using the link text
        if (self.link_text != None):
            self.url_matches_link_text = True if self.link_text == self.url else False
            link_text_results = urlparse(self.link_text)
            if (link_text_results.netloc != None and link_text_results.hostname != None):
                self.link_text_contains_url = True
                self.url_domain_matches_link_text_domain = True if self.domain == link_text_results.hostname else False
            else:
                self.link_text_contains_url = False

        return




class EmailFeatures:
    def __init__(self, email, phishiness: bool = False) -> None:
        self.email = email
        self.phishiness = phishiness
        self.from_domain = None
        self.url_feature_set = set()
        self.extractFeatures(email)
        return

    def __repr__(self) -> str:
        repr = ""
        repr += "Email:\n"
        repr += "\tPhishiness:   {}\n".format(self.phishiness)
        repr += "\tFrom domain:  {}\n".format(self.from_domain)
        repr += "\tFeatures\n"
        repr += "\t\tPhishiness:             {}\n".format(self.phishiness)
        repr += "\t\tURL count:              {}\n".format(len(self.url_feature_set))
        repr += "\t\tURL count suspicious:   {}\n".format(self.urlPhishinessCount())
        return repr

    def toMachineLearningCSV(self) -> str:
        repr = ""
        repr += "{},".format(self.phishiness)
        repr += "{},".format(len(self.url_feature_set))
        repr += "{},".format(self.urlPhishinessCount())
        return repr

    def urlPhishinessCount(self) -> int:
        url_phishiness_count = 0
        for url_set in self.url_feature_set:
            if url_set.phishiness == True:
                url_phishiness_count += 1
        return url_phishiness_count


    @staticmethod
    def getURLsFromPlaintext(plaintext: str):
        # TODO
        return []

    @staticmethod
    def getURLsFromHTML(html: str):
        # TODO
        return []

    def extractFeatures(self, email) -> None:
        message = email
        # Extract the from domain
        email_regex = re.compile("\S+@\S+")
        from_email = email_regex.findall(message['from'])[0]
        from_email = from_email.replace('<', '')
        from_email = from_email.replace('>', '')
        from_domain = None
        if ('@' in from_email):
            at_pos = from_email.find('@')
            end = len(from_email)
            from_domain = from_email[at_pos+1:end]
        self.from_domain = from_domain

        '''
        body = message.get_body().as_string()
        url_regex = re.compile("^\b(https|http):\/\/([\S]*\.[\S]*)(\/){0,1}(.*)")
        urls = url_regex.findall(body)
        print("URLs: {}".format(urls))
        '''



        # Extract all the URLs in the message and their features
        for part in message.walk():
            if (part.get_content_type() == "text/plain"):
                found_urls = EmailFeatures.getURLsFromPlaintext(part.as_string())
                # Extract bare URLs
                for url in found_urls:
                    feature_set = URLFeatures(url)
                    feature_set = self.from_domain
                    self.url_feature_set.add(feature_set)
            elif (part.get_content_type() == "text/html"):
                found_urls = EmailFeatures.getURLsFromHTML(part.as_string())
                # Extract URLs from links
                for url, link_text in found_urls:
                    feature_set = URLFeatures(url)
                    feature_set = self.from_domain
                    feature_set.link_text = link_text
                    self.url_feature_set.add(feature_set)

        return




def convertMboxToFiles(mailbox_file_name: str, output_dir: str) -> None:
    """
    Converts a single mbox file to a bunch of individual files that can be re-imported from .eml files
    """
    mb = mailbox.mbox(mailbox_file_name)
    for key in mb.iterkeys():
        message = mb[key]
        with open(output_dir + str(key) + ".eml", 'w') as f:
            try:
                f.write(message.as_string())
            except (KeyError,UnicodeEncodeError,LookupError):
                pass
            f.close()
    return

def addEMLFilenamesToList(eml_path: str, filename_list: List[str]) -> None:
    for dirpath, dirnames, filenames in os.walk(eml_path):
        for filename in filenames:
            if (filename.endswith(".eml")):
                filename_list.append(dirpath + "/" + filename)

def emailReader(filenames: List[str], output_list:List[EmailFeatures], phishiness: bool):
    for filename in filenames:
        with open(filename, 'rb') as file_pointer:
            if (file_pointer.mode == 'rb'):
                try:
                    # Read the file
                    parsed_message = BytesParser(policy=default).parse(file_pointer)
                    # Get the features
                    features = EmailFeatures(parsed_message)
                    # Export the features
                    output_list.append(features)
                except EOFError:
                    file_pointer.close()

def testUrlFeatures() -> None:
    '''
    Used to test the URLFeatures class
    '''

    # Real
    feature = URLFeatures("https://docs.python.org/3/library/mailbox.html", False)
    feature.from_domain = "python.org"
    feature.link_text = "https://docs.python.org/3/library/mailbox.html"
    feature.extractFeatures()
    print(feature)
    print(feature.toMachineLearningCSV())

    # Suspicious
    feature = URLFeatures("https://docs.python.org.phishing.org/3/library/mailbox.html", True)
    feature.from_domain = "fake.python.org"
    feature.link_text = "Login Here"
    feature.extractFeatures()
    print(feature)
    print(feature.toMachineLearningCSV())

    # Suspicious, only from context
    feature = URLFeatures("https://docs.python.org.phishing.org/3/library/mailbox.html", True)
    feature.from_domain = "fake.python.org"
    feature.extractFeatures()
    print(feature)
    print(feature.toMachineLearningCSV())

    # Suspicious, only link text context
    feature = URLFeatures("https://docs.python.org.phishing.org/3/library/mailbox.html", True)
    feature.link_text = "Login Here"
    feature.extractFeatures()
    print(feature)
    print(feature.toMachineLearningCSV())

    # Suspicious, no context
    feature = URLFeatures("https://docs.python.org.phishing.org/3/library/mailbox.html", True)
    feature.extractFeatures()
    print(feature)
    print(feature.toMachineLearningCSV())

    return

def testEmailFeatures() -> None:
    '''
    Used to test the EmailFeatures class
    '''

    return

def main():

    # Convert mbox files to folders with individual .eml meessages
    #convertMboxToFiles('samples/account_name/fish.mbox', 'samples/account_name/fish/')
    #convertMboxToFiles('samples/account_name/phish.mbox', 'samples/account_name/phish/')


    testUrlFeatures()


    normal_email_filenames = []
    suspicious_email_filenames = []
    addEMLFilenamesToList("samples/uo/", normal_email_filenames)

    print("Normal filenames:     {}".format(len(normal_email_filenames)))
    print("Suspicious filenames: {}".format(len(suspicious_email_filenames)))

    # Import all the emails
    email_features_list: List[EmailFeatures] = []
    emailReader(normal_email_filenames, email_features_list, False)

    # Display their info
    for email_features in email_features_list:
        print(email_features)





if __name__ == "__main__":
    main()
