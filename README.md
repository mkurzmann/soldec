# Soldec
Smart contracts are often employed for applications that handle valuable assets and if erroneous, may cause money losses. 
Therefore, the examination of the EVM bytecode of smart contracts is a valuable means for analysis. However, this bytecode 
is hard to read for humans. Even though many applications are developed in Solidity, the code of these applications often 
is only available as EVM bytecode after compilation. Decompilation is therefore required, which translates the bytecode 
back into a higher programming language in order to make it easier to read.

Since there is still a need for research in regard to the decompilation of EVM bytecode, the aim of this project was to 
investigate to what extent this issue can be solved. We survey existing tools and methods for decompiling smart contracts. 
Moreover, we explore the structure of EVM bytecode. Based on these results we develop the prototype Soldec, which extends 
and improves on the open-source decompiler Erays. Finally, we evaluate the prototype regarding its ability to reconstruct 
Solidity-like code.

Soldec (short for Solidity Decompiler) is an Ethereum smart contract reverse engineering tool which is is written in 
Python 3. As already mentioned it is based on Erays (https://github.com/teamnsrg/erays) and it was developed further 
with the goal to make the output more Solidity-like. This was part of the master thesis
_Decompilation of EVM Bytecode_ which is located in https://github.com/mkurzmann/soldec/thesis.

### Improvements
The improvements that were made on Erays are listed bellow:
- numerous improvements of the readability of the decompiled code such as CLI output and contract structure
- splitting of the deployment bytecode in creation (constructor detection) and runtime code (function detection)
- splitting of bytecodes containing more than one contracts
- metadata hash detection and removal
- function signature detection as far as possible
- event signature detection as far as possible
- distinction between require and assert
- rewriting of some memory actions
- rewriting of some storage actions
- detection of unstructured (combined) conditions
- detection of do-while loops
- detection of break instructions
- little detection of some typ information

### User Guide
First you need install graphviz, since Erays uses PDF outputs which are not removed in Soldec.
```sh
$ sudo apt install graphviz
```
To run Soldec, use the structurer on a file that contains contract hex string, for example:
```sh
$ python structurer.py temp/basictoken.hex
```
Now a decompiled version of the Solidity-Contract located in ```temp/basictoken.sol`` should appear on the CLI.

If the complain was:
```sh
GARBAGE bytcode encountered
```
Then its probably because the bytecode is added after this tool was built (or the contract is nonsense).
