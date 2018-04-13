IP_REGEX = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$|^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/g;

const { execFile } = require('child_process');
const MODSECPREFIX = "ModSecBlockedIPs_";

var ModSecWinAPI = function() {
        
        var addIPlocal = function(dir, ip, ruleName) {
                //check ip is already added to ModSEC rules
                execFile('netsh', ['advfirewall', 'firewall','show', 'rule', 'name=' + ruleName], (error, stdout, stderr) => {
                        if(error) {
                                if(stdout.indexOf("No rules match") < 0) {
                                        console.log("Error on rule " + ruleName + " check!");
                                        throw error;
                                }
                                console.log("Rule for IP does not already exist, adding " + ip + " in rule " + ruleName);
                                //add rule: it might not work (UNTESTED)
                                execFile('netsh', ['advfirewall', 'firewall', 'add', 'rule', 'name='+ ruleName, 'protocol=any', 'dir=' + dir, 'action=block', 'remoteip=' + ip], (errorAdd, stdoutAdd, stderrAdd) => {
                                        if(errorAdd) {
                                                console.log("Error on rule " + ruleName + " adding " + dir + "bound!");
                                                //throw errorAdd;
                                        }
                                        console.log("Successfully added " + dir + "bound " + ruleName);
                                        console.log(stdoutAdd);
                                });
                        }
                });       
        }
        
        //Add IPs to block function
        this.addIPs = function(ipList) {
                for (i = 0; i < ipList.length; i++) {
                        if(ipList[i].match(IP_REGEX)) {
                                console.log(ipList[i] + " is a valid IP");
                                //declare internal iterator position for execDir
                                let pos = i;
                                let ipRuleNameIn =  MODSECPREFIX + "IN_" + ipList[i].replace(/:/g,"_");
                                let ipRuleNameOut =  MODSECPREFIX + "OUT_" + ipList[i].replace(/:/g,"_");

                                //inbound
                                addIPlocal("in", ipList[i], ipRuleNameIn);
                                //outbound
                                addIPlocal("out", ipList[i], ipRuleNameOut);

                        } else {
                                console.log(ipList[i] + " is not a valid IP, bypassing");
                        }
                }
        }

        var deleteIPlocal = function(ruleName) {
                console.log("Deleting rule " + ruleName);
                execFile('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name='+ ruleName], (errorDelete, stdoutDelete, stderrDelete) => {
                        if(errorDelete) {
                                if(stdoutDelete.indexOf("No rules match") < 0) {
                                        console.log("Error on rule " + ruleName + " deleting!");
                                        throw errorDelete;
                                }
                                console.log("Rule " + ruleName + " does not exist, bypassing");
                                return true;
                        }
                        console.log("Successfully deleted " + ruleName);
                        console.log(stdoutDelete);
                });
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

                                //inbound
                                deleteIPlocal(ipRuleNameIn);
                                //outbound
                                deleteIPlocal(ipRuleNameOut);

                        } else {
                                console.log(ipList[i] + " is not a valid IP, bypassing");
                        }
                }
        }
}

module.exports = ModSecWinAPI
