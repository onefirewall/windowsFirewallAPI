# windowsFirewallAPI

#To execute app
node app.js

Methods to add and delete blocking rules in windows firewall, inbound and outbound.
If windows firewall is disabled it will still add/delete rules, but of course they will not be used.

It throws errors if something not foreseen happens.
Ignores entry when IP is not valid and does nothing when it tries to delete a not existent rule.
