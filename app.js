var ModSecWinAPI = require('./ModSecWinAPI.js');
var ipList = [ "192.168.1.2", "notAnIp", "2001:db8::1:0:0:1"];

var winAPI = new ModSecWinAPI();

winAPI.addIPs(ipList);
//winAPI.deleteIPs(ipList);
