IP_REGEX = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/g;

const { execFile } = require('child_process');
const MODSECPREFIX = "ModSecBlockedIPs_";

var ModSecWinAPI = function() {
        //Add IPs to block function
        this.addIPs = function(ipList) {
                for (i = 0; i < ipList.length; i++) {
                        if(ipList[i].match(IP_REGEX)) {
                                console.log(ipList[i] + " is a valid IP");
                                //declare internal iterator position for execDir
                                let pos = i;
                                let ipRuleNameIn =  MODSECPREFIX + "IN_" + ipList[i].replace(/:/g,"_");
                                let ipRuleNameOut =  MODSECPREFIX + "OUT_" + ipList[i].replace(/:/g,"_");
                                //check ip is already added to ModSEC rules
                                //inbound
                                execFile('netsh', ['advfirewall', 'firewall','show', 'rule', 'name=' + ipRuleNameIn], (errorIn, stdoutIn, stderrIn) => {
                                        if(errorIn) {
                                                if(stdoutIn.indexOf("No rules match") < 0) {
                                                        console.log("Error on rule " + ipRuleNameIn + " check!");
                                                        throw errorIn;
                                                }
                                                console.log("Rule for IP does not already exist, adding " + ipList[pos] + " in rule " + ipRuleNameIn);
                                                //add rule IN: it might not work (UNTESTED)
                                                execFile('netsh', ['advfirewall', 'firewall', 'add', 'rule', 'name='+ ipRuleNameIn, 'protocol=any', 'dir=in', 'action=block', 'remoteip=' + ipList[pos]], (errorAddIn, stdoutAddIn, stderrAddIn) => {
                                                        if(errorAddIn) {
                                                                console.log("Error on rule " + ipRuleNameIn + " adding inbound!");
                                                                //throw errorAddIn;
                                                        }
                                                        console.log("Successfully added inbound " + ipRuleNameIn);
                                                        console.log(stdoutAddIn);
                                                });
                                        }
                                });
                                //outbound
                                execFile('netsh', ['advfirewall', 'firewall','show', 'rule', 'name=' + ipRuleNameOut], (errorOut, stdoutOut, stderrOut) => {
                                        if(errorOut) {
                                                if(stdoutOut.indexOf("No rules match") < 0) {
                                                        console.log("Error on rule " + ipRuleNameOut + " check!");
                                                        throw error;
                                                }
                                                console.log("Rule for IP does not already exist, adding " + ipList[pos] + " in rule " + ipRuleNameOut);
                                                //add rule OUT: it might not work (UNTESTED)
                                                execFile('netsh', ['advfirewall', 'firewall', 'add', 'rule', 'name='+ ipRuleNameOut, 'protocol=any', 'dir=out', 'action=block', 'remoteip=' + ipList[pos]], (errorAddOut, stdoutAddOut, stderrAddOut) => {
                                                        if(errorAddOut) {
                                                                console.log("Error on rule " + ipRuleNameOut + " adding outbound!");
                                                                //throw errorAddOut;
                                                        }
                                                        console.log("Successfully added outbound " + ipRuleNameOut);
                                                        console.log(stdoutAddOut);
                                                });
                                        }
                                });
                        } else {
                                console.log(ipList[i] + " is not a valid IP, bypassing");
                        }
                }
        }

        //Delete blocked IPs function
        this.deleteIPs = function(ipList) {
                for (i = 0; i < ipList.length; i++) {
                        if(ipList[i].match(IP_REGEX)) {
                                console.log(ipList[i] + " is a valid IP");
                                //declare internal iterator position for execDir
                                let pos = i;
                                let ipRuleNameIn =  MODSECPREFIX + "IN_" + ipList[i].replace(/:/g,"_");
                                let ipRuleNameOut =  MODSECPREFIX + "OUT_" + ipList[i].replace(/:/g,"_");
                                //delete rule: it might not work (UNTESTED)
                                console.log("Deleting rule " + ipRuleName);
                                //inbound
                                execFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name='+ ipRuleNameIn], (errorDelete, stdoutDelete, stderrDelete) => {
                                        if(errorDelete) {
                                                if(stdoutDelete.indexOf("No rules match") < 0) {
                                                        console.log("Error on rule " + ipRuleNameIn + " deleting!");
                                                        throw errorDelete;
                                                }
                                                console.log("Rule " + ipRuleNameIn + " does not exist, bypassing");
                                                return true;
                                        }
                                        console.log("Successfully deleted " + ipRuleNameIn);
                                        console.log(stdoutDelete);
                                });
                                //outbound
                                execFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name='+ ipRuleNameOut], (errorDelete, stdoutDelete, stderrDelete) => {
                                        if(errorDelete) {
                                                if(stdoutDelete.indexOf("No rules match") < 0) {
                                                        console.log("Error on rule " + ipRuleNameOut + " deleting!");
                                                        throw errorDelete;
                                                }
                                                console.log("Rule " + ipRuleNameOut + " does not exist, bypassing");
                                                return true;
                                        }
                                        console.log("Successfully deleted " + ipRuleNameOut);
                                        console.log(stdoutDelete);
                                });
                        } else {
                                console.log(ipList[i] + " is not a valid IP, bypassing");
                        }
                }
        }
}

module.exports = ModSecWinAPI
