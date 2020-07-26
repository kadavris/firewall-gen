# firewall-gen
 iptables multi-interface firewall generator
### Features:
* class-based access configuration with inheritance
* MAC access filters. Per-device settings.
* Default network settings for unknown devices, like Wi-Fi clients
* Pre-filters for common attack types with or without logging
* Multiple networks/IPs support per interface
* 2 fixed-purpose interfaces: internet and internal lan
* unlimited secondary physical interfaces
* unlimited virtual interfaces like containers
* Pre-flight checks of configuration
* probably some more...

### how to start
* Check firewall4-gen.conf.sample for complete description and example.
* Make your own firewall4-gen.conf
* Run firewall4-gen.pl
* Check output for error messages
* Check created file for problems
* Run iptables-restore -v < your_file

Remember that changing firewall rules from remote connection may drop you out if problem occur!

