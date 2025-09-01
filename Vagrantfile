Vagrant.configure("2") do |config|
  config.vbguest.installer_options = { allow_kernel_upgrade: false }
  config.vbguest.auto_update = false
  config.vm.provider "virtualbox" do |vb|
    vb.customize ["modifyvm", :id, "--cableconnected1", "on"]
    vb.customize ["modifyvm", :id, "--uart1", "0x3F8", "4"]
    vb.customize ["modifyvm", :id, "--uartmode1", "file", File::NULL]
  end

  config.vm.define "admin" do |admin|
    admin.ssh.key_type = "ed25519"
    admin.vm.box = "bento/ubuntu-24.04"
    admin.vm.network "private_network", ip:"192.168.56.39"
    admin.vm.hostname = "admin"
    admin.vm.boot_timeout = 600
    admin.vm.provision "shell",
      path: "./scripts/admin_server_installation.sh"
  end

  config.vm.define "vault" do |vault|
    vault.ssh.key_type = "ed25519"
    vault.vm.box = "bento/ubuntu-24.04"
    vault.vm.network "private_network", ip:"192.168.56.40"
    vault.vm.network "forwarded_port", guest: 8200, host: 8200
    vault.vm.hostname = "vault"
    vault.vm.boot_timeout = 600
    vault.vm.provision "shell",
      path: "./scripts/vault_server_installation.sh"
  end

  (1..2).each do |i|
    config.vm.define "server0#{i}" do |server|
      server.ssh.key_type = "ed25519"
      server.vm.box = "bento/ubuntu-24.04"
      server.vm.network "private_network", ip:"192.168.56.4#{i}"
      server.vm.hostname = "server0#{i}"
      server.vm.boot_timeout = 600
      server.vm.provision "shell",
        path: "./scripts/vault_ssh_helper_installation.sh"
    end
  end
end
