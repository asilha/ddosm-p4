# About ddosm-p4

This is a work in progress based in a fork of [ddosd-p4](https://github.com/aclapolli/ddosd-p4). 
The target is the `simple_switch` variation of the P4 behavioral model software reference implementation.

## Getting Started

These instructions will guide you to run the mitigation mechanism on the target switch.
We recommend using an Ubuntu 16.04 virtual machine.

### Prerequisites

This work depends on extended versions of the P4 reference compiler (p4c) and the behavioral model, which implement custom hash functions.  
You need to clone the repositories and follow the installation guidelines within:

- [behavioral-model](https://github.com/aclapolli/behavioral-model)
- [p4c](https://github.com/aclapolli/p4c)

### Building
Ensure that the `p4c` binary is within your `$PATH` and run:
```
git clone https://github.com/asilha/ddosm-p4.git
cd ddosm-p4
make
```

This process builds the P4 program into `./build/ddosm.json`

## License
This repository is licensed under the GNU General Public License v3.0 (check [LICENSE](LICENSE) for details).
