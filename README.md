# windowsFirewallAPI

#To execute app
node app.js

Methods to add and delete blocking rules in windows firewall, inbound and outbound.
If windows firewall is disabled it will still add/delete rules, but of course they will not be used.
Windows firewall status is a merge of more than one setting (group policy and local policy): see https://social.technet.microsoft.com/Forums/windowsserver/en-US/4d8678e2-5653-4fd2-b275-62e0e7008ff9/conflicting-display-of-windows-firewall-setting-from-gui-and-netsh-advfirewall?forum=winserverGP

It throws errors if something not foreseen happens.
Ignores entry when IP is not valid and does nothing when it tries to delete a not existent rule.
