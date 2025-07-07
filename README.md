# 🔐 RRS, LogRRS, and RRS-2007 Scheme Implementations

This repository contains the Python implementations of three cryptographic ring signature schemes:

- ✅ **RRS** – Our proposed Revocable Ring Signature scheme.
- ✅ **LogRRS** – Our Logarithmic size RRS scheme using NISA (Non Interactive Sum Argument System).
- ✅ **RRS-2007** – The foundational scheme proposed by Liu et al. in 2007.

These implementations are designed for research and experimental purposes, providing a foundation for benchmarking and extending ring signature cryptographic protocols.

---

## 📁 Repository Structure

```bash
RRS-LogRRS-RRS-2007/
├── RRS/          # Our proposed RRS scheme
├── LogRRS/       # Logarithmic RRS implementation
├── RRS2007/      # Liu et al.'s 2007 RRS scheme
└── README.md     # Project documentation
```

---

## ⚙️ Requirements

- Python 3.8+
- Charm-Crypto >= 0.43
- fastecdsa >= 3.0.1
- sympy >= 1.12

Install required dependencies using pip:

```bash
pip install requirements.txt
```

---

## 🚀 Running the Code

**If you want to run it in google colab you can refer to the file installation of charm crypto on collab**.
Navigate to the desired scheme folder and execute the main test script. For example:

```bash
cd RRS and LOG-RRS/
python logrrs.py
```



---


## 🔬 Use Case

These schemes are designed to support **privacy-preserving authentication** with **revocation** capabilities, making them suitable for secure applications such as:

- VANETs (Vehicular Ad-hoc Networks)
- E-voting systems
- Decentralized identity systems

---

## 📌 Notes

- This repository is intended **for academic and research use only**.
- The implementations are experimental and **not production-ready**.
- No formal license is currently associated with this project.

---

## 📫 Contact

For questions, collaborations, or feedback:

**Khandava Kishan**  
📧 [khandavakishan1104@gmail.com](mailto:khandavakishan1104@gmail.com)  
GitHub: [@kishan1104](https://github.com/kishan1104)

---

> ⭐ If you find this work useful, consider starring the repository to support future research.

