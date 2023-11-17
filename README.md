# RHEL PKI MFA

This is for RHEL 7 & 8. It requires that you're already joined to the AD Domain with SSSD and that you don't have SELinux disabled. Ansible also needs to already be a sudo-able user in the target system(s).


Override variables in the `enable-rhel-pki-mfa.yml` as needed for the location. Remember to add hosts to the inventory (`hosts`) file. Additional config options are in the `ansible.cfg`, but they are pretty boiler-plate. Modify this playbook and inventory to suit your automation and scaling needs.

To check how this playbook will affect your system, here is some recommended execution syntax (some tasks may fail simply due to lackluster support for Check Mode):

`$ ansible-playbook -C -D -k enable-rhel-pki-mfa.yml -e "my_host=hostnameHere" -e "ignore_task_failures=yes" -u remoteUsername -vv`

To execute the playbook, remove the testing-related syntax. For instance:

`$ ansible-playbook -k enable-rhel-pki-mfa.yml -e "my_host=hostnameHere" -u remoteUsername -vv`


(Note: only use -k if youre SSHing with passwords instead of keys; use -C if you want to go into check mode instead of making changes; you can omit the -u setting if your remote user is specififed correctly in the ansible.cfg)
