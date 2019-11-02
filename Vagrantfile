Vagrant.configure("2") do |config|
	config.vm.box = "bento/opensuse-leap-15.0"
	config.ssh.insert_key = false
	config.vm.provision "shell", path: "zypper.sh"
	config.vm.provision "shell", path: "system_prepare.sh"
end
