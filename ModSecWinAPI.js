IP_REGEX = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/g;

const { execFile } = require('child_process');
const MODSECPREFIX = "ModSecBlockedIPs_";

var ModSecWinAPI = function() {
        //Add IPs to block function
        this.addIPs = function(ipList) {
                for (i = 0; i < ipList.length; i++) {
                        if(ipList[i].match(IP_REGEX)) {
                                console.log(ipList[i] + " is a valid IP");
                                var ipRuleName =  MODSECPREFIX + ipList[i].replace(/:/g,"_");
                                //check ip is already added to ModSEC rules
                                execFile('netsh', ['advfirewall', 'firewall','show', 'rule', 'name=' + ipRuleName], (error, stdout, stderr) => {
                                        if(error) {
                                                if(stdout.indexOf("No rules match") < 0) {
                                                        console.log("Error on IP " + ipList[i] + " check!");
                                                        throw error;
                                                }
                                                console.log("Rule for IP does not already exist, adding " + ipList[i] + " in rule " + ipRuleName);
                                                //add rule: it might not work (UNTESTED)
                                                execFile('netsh', ['advfirewall', 'firewall', 'add', 'rule', 'name='+ ipRuleName, 'protocol=any', 'dir=in', 'action=block', 'remoteip=' + ipList[i]], (errorAdd, stdoutAdd, stderrAdd) => {
                                                        if(errorAdd) {
                                                                console.log("Error on IP " + ipList[i] + " adding!");
                                                                throw errorAdd;
                                                        }
                                                        console.log("Successfully added " + ipRuleName);
                                                        console.log(stdoutAdd);
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
                                var ipRuleName =  MODSECPREFIX + ipList[i].replace(/:/g,"_");
                                //delete rule: it might not work (UNTESTED)
                                console.log("Deleting rule " + ipRuleName);
                                execFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name='+ ipRuleName], (errorDelete, stdoutDelete, stderrDelete) => {
                                        if(errorDelete) {
                                                if(stdoutDelete.indexOf("No rules match") < 0) {
                                                        console.log("Error on IP " + ipList[i] + " deleting!");
                                                        throw errorDelete;
                                                }
                                                console.log("Rule " + ipRuleName + " does not exist, bypassing");
                                                return true;
                                        }
                                        console.log("Successfully deleted " + ipRuleName);
                                        console.log(stdoutDelete);
                                });
                        } else {
                                console.log(ipList[i] + " is not a valid IP, bypassing");
                        }
                }
        }
}

module.exports = ModSecWinAPI
