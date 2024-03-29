# About

This is the central code repository of the in-network DDoS attack detection and mitigation mechanism we proposed in the journal article "EUCLID: A Fully In-Network, P4-based Approach for Real-Time DDoS Attack Detection and Mitigation" (in _IEEE Transactions on Network and Service Management_,
[DOI: 10.1109/TNSM.2020.3048265](https://doi.org/10.1109/TNSM.2020.3048265)).

EUCLID adds DDoS attack mitigation capabilities and several other improvements to [ddosd-p4](https://github.com/aclapolli/ddosd-p4), which performs attack detection.

The target architecture for this proof-of-concept code is the `simple_switch` variation of the P4 behavioral model software reference implementation.

## Getting Started

These instructions will guide you to run the mitigation mechanism on the target switch.
We recommend using an Ubuntu 16.04 virtual machine.

### Prerequisites

This work depends on extended versions of the P4 reference compiler (p4c) and the behavioral model (bmv2), which implement custom hash functions.  
You need to clone the repositories and follow the installation guidelines within:

- [bmv2](https://github.com/asilha/p4lang-behavioral-model/tree/euclid)
- [p4c](https://github.com/asilha/p4lang-p4c/tree/euclid)

### Building

Ensure that the `p4c` binary is within your `$PATH` and run:

```console
git clone https://github.com/asilha/ddosm-p4.git
cd ddosm-p4
make
```

This process builds the P4 program into `./build/ddosm.json`

We plan on making available a Dockerfile to simplify building and experiments.

## License

This repository is licensed under the GNU General Public License v3.0 (check [LICENSE](LICENSE) for details).

## Citation

If you use this repository in your research, please cite:

```bibtex
@Article{Euclid,
  author    = {Ilha, A. S. and Lapolli, \^{A}. C. and Marques, J. A. and Gaspary, L. P.},
  journal   = {IEEE Transactions on Network and Service Management},
  title     = {{Euclid: A Fully In-Network, P4-Based Approach for Real-Time DDoS Attack Detection and Mitigation}},
  year      = {2021},
  month     = {sep},
  number    = {3},
  pages     = {3121--3139},
  volume    = {18},
  doi       = {10.1109/TNSM.2020.3048265},
  publisher = {Institute of Electrical and Electronics Engineers ({IEEE})},
}
```
