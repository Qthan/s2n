# Constant Time Verification Tests for s2n

This repository contains tests which ensure that key s2n functions
are not susceptible to timing attacks.

For more details, see https://github.com/awslabs/s2n/issues/463
NOTE: Much of this information was discssed in greater detail in the [s2n blog post:](https://aws.amazon.com/blogs/security/s2n-and-lucky-13/)


## What are timing side channels

Crypographic protocols such as TLS are supposed to keep secret information secret.
They do this by ensuring that WHICH bytes go over the wire is hidden using encryption.
However, if the code is not carefully written, WHEN bytes go over the wire may depend
on values that were supposed to remain secret.

For example, if code checks a password as follows

```
for (i = 0; i < length; ++i) {
  if password[i] != input[i] {
    send("bad password");
  }
}
```
then the amount of time until the reply message is received will depend on which byte in the password
is incorrect.  An attacker can simply guess
  * a*******
  * b*******
  * c*******

until the time to receive the error message changes, and then they know the first letter in the password.
Repeating for the remaining characters turns an exponential guessing challenge into a linear one.

##Lucky 13: a quick recap

In February 2013, Nadhem J. AlFardan and Kenny Paterson of the Information Security Group at Royal Holloway, University of London, published the Lucky 13 attack against TLS. Adam Langley’s blog post on the topic is a great detailed summary of the attack and how it operates and how It was mitigated In OpenSSL.

A brief synopsis is that Lucky 13 is an “Active Person in the Middle” attack against block ciphers where an attacker who is already capable of intercepting and modifying your traffic may tamper with that traffic in ways that allow the attacker to determine which portions of your traffic are encrypted data, and which which portions of your traffic are padding (bytes included to round up to a certain block size).

The attacker’s attempt to tamper with the traffic is detected by the design of the TLS protocol, and triggers an error message. The Lucky 13 research showed that receiving this error message can take a different amount of time depending on whether real data or padding was modified. That information can be combined with other cryptographic attacks to recover the original plaintext.

## s2n countermeasures against timing side channels
s2n has included two different forms of mitigation against the Lucky 13 attack since release: first by minimizing the timing difference mentioned above, and second, by masking any difference by including a delay of up to 10 seconds whenever any error is triggered.  In particular,
* s2n verifies CBC padding in constant time regardless of the amount of padding
* s2n counts the number of bytes handled by HMAC and making this equal in all cases, a “close to constant time” technique that completely preserves the standard HMAC interface.
* add a single new call that always performs two internal rounds of compression, even if one may not be necessary. This ensures that the same number of hash compression rounds always occur.

## How does Sidewinder prove the correctness of code blinding countermeasures
Mathematically, a program `P(secret, public)` has runtime `Time(P(secret,public))`. A program has a timing side-channel of delta if `|Time(P(secret_1,public)) - Time(P(secret_2,public))| = delta`.  If we can represent `Time(P(secret,public))` as a mathematical formula, we can use a theorem prover to mathematically prove that the timing leakage of the program, for all choices of `secret_1, secret_2`, is less than `delta`. 

Sidewinder proceedes in several steps:
1. Compile the code to llvm bitcode - this allows Sidewinder to accuratly represent the effect of compiler optimizations on runtime
2. Use LLVM's timing model to associate every bitcode operation with a timing cost
3. Use SMACK to compile the annotated LLVM code to BoogiePL (this represents `(P(secret,public))` in the above formula
4. Use bam-bam-boogieman to
  * Add a timing cost variable to the program, generating `Time(P(secret,public))`
  * Make two copies of the resulting program, one which has inputs `(secret_1, public)`, the other of which has inputs `(secret_2, public)`
  * Assert that the difference in time between the two programs is less than `delta`
5. Use boogie to prove (via the z3 theorem prover) that either
  * The time is indeed less than `delta`
  * or, the time is greater than `delta`, in which case the prover can emit a trace leading to the error


## How to execute the tests

### Install the dependencies
Running these tests will require the following dependencies
(tested on Ubuntu 14.04).  To see how to install this on a clean ubuntu machine, 
take a look at the .travis scripts in this repo.

- bam-bam-boogieman 
- SMACK and all its dependencies
  - The easiest way to get these is to use the build.sh in smack/bin
  - Ensure that all of the installed depencies are on the $PATH
  - source the smack.environment that the smack build script creates

### Execute the test

```
cd tests/sidewinder/working/s2n-cbc
./clean.sh
./run.sh

If the tests pass, you will see a message like: Boogie program verifier finished with 1 verified, 0 error

If the tests fail, you will see a message like: Boogie program verifier finished with 0 verified, 1 error
```


## Questions?
contact dsn@amazon.com