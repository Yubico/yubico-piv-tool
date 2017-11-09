Vagrant VM for development
===

Usage:

    alice@work $ cd yubico-piv-tool/vagrant/development
    alice@work $ vagrant up
    alice@work $ vagrant ssh
    ubuntu@ubuntu-xenial $ cd /vagrant
    ubuntu@ubuntu-xenial $ autoreconf --install
    ubuntu@ubuntu-xenial $ ./configure
    ubuntu@ubuntu-xenial $ make
    ubuntu@ubuntu-xenial $ sudo make install
    ubuntu@ubuntu-xenial $ yubico-piv-tool --help
    ubuntu@ubuntu-xenial $ exit
    alice@work $ vagrant destroy
