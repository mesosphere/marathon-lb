# Changelog

## 0.3.0 (upcoming)

* [EOS-1038] Output marathon-lb-sec logs to stdout
* [EOS-987] Marathon-lb-sec logging format should comply with standard
* Updated kms_utils version to 0.4.0
* Included b-log version 0.4.0
* Updated Marathon-LB main version v1.11.3
* Bug fixing with race conditions
* Bug fixing with dead connections to Vault
* Ensure the default marathon-lb certificate to be present by SNI if there's no certificate for the concrete app
* Add iptables rules in position 2 if a calico rule is present

## 0.2.0 (December 19, 2017)

* [EOS-852] Expose certificates per app
* Python kms_utils wrapper
* Updated kms_utils version to 0.3.0

## 0.1.0 (November 22, 2017)

* [EOS-568] Implement dynamic authentication in Marathon-lb entrypoint
* Marathon-LB main version v1.10.3
