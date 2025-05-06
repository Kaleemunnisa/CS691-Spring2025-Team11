// Load Config File
function loadConfig() {
    return fetch('config.env')
        .then(response => response.text())
        .then(text => {
            let lines = text.split('\n');
            for (let line of lines) {
                let [key, value] = line.split('=').map(s => s.trim());
                if (key === 'IPINFO_TOKEN') {
                    let ipinfoToken = value.replace(/['"]/g, ''); // Remove quotes if present
                    return ipinfoToken; // Return the key
                }
            }
            throw new Error("IPINFO_TOKEN not found in config.env");
        })
        .catch(error => console.error('Error loading config:', error));
}

loadConfig().then(ipinfoToken => {

    // collect_info.js

    function getPublicIPInfo() {
        return fetch(`https://ipinfo.io/json?token=${ipinfoToken}`)
            .then(response => response.json())
            .catch(error => {
                console.error('Error fetching IP info:', error);
                return null;
            });
    }

    function getBrowserDeviceInfo() {
        return {
            browser: platform.name + ' ' + platform.version,
            os: platform.os.family + ' ' + platform.os.version,
            device: platform.product || 'Desktop'
        };
    }

});