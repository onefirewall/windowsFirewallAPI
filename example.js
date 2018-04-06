const { execFile } = require('child_process');

//just prints the firewall status
execFile('netsh', ['advfirewall', 'show', 'allprofiles'], (error, stdout, stderr) => {
    if(error) {
	console.log("Error!");
	throw error;
    }
	console.log(stdout);
});
