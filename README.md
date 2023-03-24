# magic-scanner
Smaller, faster full port scanning!

show help
```shell
./magic-scanner -h
```
```shell
Usage: magic-scanner [OPTIONS] --address <ADDRESS>

Options:
  -a, --address <ADDRESS>  work address, accept ip, subnet mask, ip segment./n
      --ping               whether to ping before work
  -p, --ports <PORTS>      work port, accept port, port range
  -h, --help               Print help
  -V, --version            Print version
```

running scan
```shell
./magic-scnner -a 127.0.0.1 -p 1-10,21,30-40,55743
```
```shell
2023-03-24T09:36:29.439988Z  INFO magic_scanner:  __  __          _____ _____ _____  _____  _____          _   _ _   _ ______ _____  
2023-03-24T09:36:29.440512Z  INFO magic_scanner: |  \/  |   /\   / ____|_   _/ ____|/ ____|/ ____|   /\   | \ | | \ | |  ____|  __ \ 
2023-03-24T09:36:29.444735Z  INFO magic_scanner: | \  / |  /  \ | |  __  | || |    | (___ | |       /  \  |  \| |  \| | |__  | |__) |
2023-03-24T09:36:29.447353Z  INFO magic_scanner: | |\/| | / /\ \| | |_ | | || |     \___ \| |      / /\ \ | . ` | . ` |  __| |  _  / 
2023-03-24T09:36:29.451165Z  INFO magic_scanner: | |  | |/ ____ \ |__| |_| || |____ ____) | |____ / ____ \| |\  | |\  | |____| | \ \ 
2023-03-24T09:36:29.453484Z  INFO magic_scanner: |_|  |_/_/    \_\_____|_____\_____|_____/ \_____/_/    \_\_| \_|_| \_|______|_|  \_\
2023-03-24T09:36:29.472005Z  INFO magic_scanner: address: {127.0.0.1}
2023-03-24T09:36:29.472134Z  INFO magic_scanner: ports size: 23
2023-03-24T09:36:29.481592Z  INFO magic_scanner::scanner: 127.0.0.1:55743 [TCP|*]
2023-03-24T09:36:29.481638Z  INFO magic_scanner::scanner: run scan socket finished.
2023-03-24T09:36:29.481664Z  INFO magic_scanner: running end.
```