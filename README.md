# The Naibbe Cipher: Scribal Habits Simulation

> **Note:** This repository is a fork of Michael A. Greshko's original Naibbe cipher implementation. It extends the codebase by adding simulations of scribal habits (`naibbe_habit.py` and `naibbe_quire.py`).
> 
> This implementation was created in the context of the digital humanities exercise "Das Voynich Manuskript als Forschungsobjekt" at the IDH (Institut für Digital Humanities), University of Cologne.

## Project Description

While the original Naibbe cipher successfully encrypts Latin and Italian texts into Voynich-like ciphertext, this fork investigates the impact of simulated *scribal habits* on the statistical properties of the resulting text. By implementing these habits, we aim to test hypotheses regarding the distinct autocorrelations found in the original Voynich Manuscript.

This project is an educational exploration within the Digital Humanities, building upon the theoretical foundations laid by Greshko's work.

---

## Original Work: The Naibbe Cipher

This project builds entirely on the work of Michael A. Greshko. The original repository contains the foundational code and datasets associated with the following paper:

> Greshko, Michael A. (2025). The Naibbe cipher: a substitution cipher that encrypts
Latin and Italian as Voynich Manuscript-like ciphertext.
Cryptologia. https://doi.org/10.1080/01611194.2025.2566408
  
### Original Abstract

In the work represented here and in the associated study, I investigate
the hypothesis that the Voynich Manuscript (MS 408, Yale University Beinecke
Library) is compatible with being a ciphertext by attempting to develop a
historically plausible cipher that can replicate the manuscript’s unusual
properties. The resulting cipher—a verbose homophonic substitution cipher I call
the Naibbe cipher—can be done entirely by hand with 15th-century materials, and
when it encrypts a wide range of Latin and Italian plaintexts, the resulting
ciphertexts remain fully decipherable and also reliably reproduce many key
statistical properties of the Voynich Manuscript at once. My results suggest
that the so-called “ciphertext hypothesis” for the Voynich Manuscript remains
viable, while also placing constraints on plausible substitution cipher
structures.

### Original Data and extended output

Additional datasets, including the original Microsoft Excel implementations of
the Naibbe cipher and Voynichesque, can be found at:
https://doi.org/10.5281/zenodo.16415087

Extensive discussion of a preprint version of this paper can be accessed at:
https://www.voynich.ninja//thread-4848.html

# License and copyright

Unless otherwise indicated, the source code contained in
this repository is provided under the modified MIT license below.

---

Copyright (c) 2025, Michael A. Greshko.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software, datasets, and associated documentation files (the "Software
and Datasets"), to deal in the Software and Datasets without restriction,
including without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software and Datasets, and to
permit persons to whom the Software is furnished to do so, subject to the
following conditions:

- The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software and Datasets.
- Any publications making use of the Software and Datasets, or any substantial
  portions thereof, shall cite the Software and Datasets's original publication:

> Greshko, Michael A. (2025). The Naibbe cipher: a substitution cipher that encrypts
Latin and Italian as Voynich Manuscript-like ciphertext.
Cryptologia. https://doi.org/10.1080/01611194.2025.2566408
  
THE SOFTWARE AND DATASETS ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE AND DATASETS.
