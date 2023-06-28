|                    |      Num. Rounds     | Robust | Num. Signers | Parallel Secure |
|--------------------|:--------------------:|:------:|:------------:|:---------------:|
| **Stinson Strobl [^1]** |           4          |   Yes  |       t      |       Yes       |
| **Gennaro et al. [^2]** | 1 with preprocessing |   No   |       n      |        No       |
| **FROST** [^3]          | 1 with preprocessing |   No   |       t      |       Yes       |

| **Stinson Strobl** is the only implement Threshold Schemes in Horcrux. However, its worth important to note that the key generation in Horcrux is not the same as proposed in the paper. Instead its "classic" shamir secret sharing with a fully trusted dealer.  

[^1]: Stinson, D.R., Strobl, R. (2001). Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates. In: Varadharajan, V., Mu, Y. (eds) Information Security and Privacy. ACISP 2001. Lecture Notes in Computer Science, vol 2119. Springer, Berlin, Heidelberg. [](https://doi.org/10.1007/3-540-47719-5_33)https://doi.org/10.1007/3-540-47719-5_33
[^2]: Gennaro, R., Goldfeder, S. (2020). One Round Threshold ECDSA with Identifiable Abort. In: Cryptology ePrint Archive, Paper 2020/540. [](https://eprint.iacr.org/2020/540)https://eprint.iacr.org/2020/540
[^3]: Komlo, C., Goldberg, I. (2021). FROST: Flexible Round-Optimized Schnorr Threshold Signatures. In: Dunkelman, O., Jacobson, Jr., M.J., O'Flynn, C. (eds) Selected Areas in Cryptography. SAC 2020. Lecture Notes in Computer Science(), vol 12804. Springer, Cham. [](https://eprint.iacr.org/2020/852.pdf)https://eprint.iacr.org/2020/852.pdf

