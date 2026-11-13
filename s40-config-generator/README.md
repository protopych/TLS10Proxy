# Using TLS10Proxy on Nokia S40

To configure a phone to use TLS10Proxy follow the steps:

1. Make sure your current access point is valid and provides access to Internet;  
2. Find the actual APN value from your active access point: it needed to build a new custom config;  
3. Install `libwbxml` (`libwbxml2-utils` package for Debian/Ubuntu, `libwbxml` for others);
4. Run the config generator script and provide the required parameters (config name, proxy port and IP, APN):
```bash
  chmod +x gen.sh && ./gen.sh
```
5. Transfer the generated config to your phone exclusively via Bluetooth.
6. Set the config as default and activate it ("Activate default in all applications"). 
7. In your phone's browser, go to http://cert.install and save the certificate.