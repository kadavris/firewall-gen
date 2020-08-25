# firewall-gen
 iptables multi-interface firewall generator/builder

### Features:
* class-based access configuration with inheritance
* MAC access filters.
* Per-device access rules.
* Default network-wide settings for unknown devices, like Wi-Fi guest clients
* Pre-filters for common attack types with or without logging
* Multiple networks/IPs support per interface
* 1 optional, fixed-purpose interface - internet direct connection
* unlimited secondary physical interfaces
* unlimited virtual interfaces like containers, with in/out access settings
* Pre-flight checks of configuration
* probably some more...

### how to start
* Check firewall4-gen.conf.sample for complete description and example.
* Make your own firewall4-gen.conf. This is the default name for configuration file
* Run firewall4-gen.pl
* Check output for error messages
* Check created file for problems
* Run iptables-restore -v < your_file (see $save_file variable in config)

Remember that changing firewall rules from remote connection may drop you out if problem occur!
