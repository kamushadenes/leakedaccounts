import pypwned
import time
import dateutil.parser
from cefevent import CEFEvent, CEFSender
import sys

class LeakedAccounts(object):

    def __init__(self, syslog=False, hostname=None, port=None):
        self.syslog = syslog
        self.hostname = hostname
        self.port = int(port)

        if self.syslog:
            self.cefsender = CEFSender([], self.hostname, self.port)

    def get_breach_by_email(self, email):
        breaches = pypwned.getAllBreachesForAccount(email=email)
        for b in breaches:
            b['Email'] = email

        return breaches

    def get_epoch(self, dt):
        return int((time.mktime(dt.timetuple()) + dt.microsecond/1000000.0)  * 1000 )

    def cef_format(self, obj):
        for breach in obj:
            c = CEFEvent()
            c.set_field('startTime', self.get_epoch(dateutil.parser.parse(breach['BreachDate'])))
            c.set_field('endTime', self.get_epoch(dateutil.parser.parse(breach['AddedDate'])))
            c.set_field('deviceCustomString1', '|'.join(breach['DataClasses']))
            c.set_field('deviceCustomString1Label', 'Categories')
            c.set_field('message', breach['Description'])
            c.set_field('requestUrl', breach['Domain'])
            c.set_field('destinationUserName', breach['Email'])
            c.set_field('name', 'Account Breach at {}'.format(breach['Name']))
            c.set_field('deviceVendor', 'HPE Brazil SecLab')
            c.set_field('deviceProduct', 'LeakedAccounts')
            c.set_field('deviceCustomNumber1', breach['PwnCount'])
            c.set_field('deviceCustomNumber1Label', 'Pwn Count')

            yield c


    def get_breach(self, email):
        bs = self.get_breach_by_email(email)
        cs = [c for c in self.cef_format(bs)]

        return cs

    def send_log(self, log):
        if self.syslog:
            for l in log:
                self.cefsender.send_log(l)
                print(l)



if __name__ == '__main__':
    email = sys.argv[1]
    hostname = sys.argv[2]
    port = sys.argv[3]

    la = LeakedAccounts(syslog=True, hostname=hostname, port=port)

    la.send_log(la.get_breach(email))
