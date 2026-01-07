# Review 

## Logic

- Logical connectives  
$$¬p, p ∨ q, p ∧ q, p ⊕ q, p → q, p ↔ q$$ 
 
- Logical equivalence  
***De Morgan’s laws, communtative laws, distributive laws, ...***     

- Predicate logic  
contains ***variables ***    

- Quantified statements  
***universal, existential, equivalence***   

---
## Methods of Proving Theorems
- direct proof 
  - $p → q$ is proved by showing that if p is true then q follows 
- proof by contrapositive 
  - show the contrapositive $¬q → ¬p$
- proof by contradiction 
  - show that $(p ∧ ¬q)$ contradicts the assumptions 
- proof by cases 
  - give proofs for all possible cases 
- proof of equivalence 
  - $p ↔ q$ is replaced with $(p → q) ∧ (q → p)$

---
## Set and Function
- one-to-one (injective)
- onto (surjective)
- bijective (one-to-one correspondence)
- counting the number of such functions

***Big-O Notation***   

$f(n) = O(g(n))$ (reads: $f(n)$ is O of $g(n)$ ), if there exist some positive constants $C$ and $k$ such that $|f(n)| ≤ C|g(n)|$, whenever $n > k$.  

---
## Number Theory 

- Divisibility 
- Congruence relation 
- Primes 
- GCD and Euclidean Algorithm 
- Modular Inverse
  - inverse of a modulo m exist if $gcd(a,m) = 1$, $m > 1 $ 
  - Euclidean method is used to find inverses
- Chinese Remainder Theorem 
- Back substitution

---
## Cryptography 

- Fermat’s Little Theorem 
  - $a$, $p$ prime, $x !≡ 0 (mod p)$
  - $x^{p - 1} ≡ 1 (mod p)$
- Euler’s Theorem 
  - $gcd(x,n) = 1$, $x^{ϕ(n)} ≡ 1 (mod n)$
  - Primitive roots, multiplicative order 
- RSA cryptosystem 
  - $n = pq$, $ϕ(n) = (p - 1)(q - 1)$
  - $gcd(e,ϕ(n)) = 1$, $ed ≡ 1 (mod ϕ(n))$
  - $(n,e)$ public, $d$ private
  - thus $C ≡ M^e (mod n)$, ***encryption***
  - $M ≡ C^d (mod n)$, ***decryption***
  - Correctness: $X^{ed} ≡ x (mod n)$ 
  - DLP, Diffie-Hellman protocol

---
## Mathematical Induction  

**Steps:**  
1. Base Step: show $P(b)$ is true.
2. make the inductive hypothesis of either   
$$P(n − 1)$$    
or    
$$P(b) ∧ P(b + 1) ∧ · · · ∧ P(n − 1)$$
then, $∀n > b$, show either
$$P(n − 1) → P(n)$$
or
$$P(b) ∧ P(b + 1) ∧ · · · ∧ P(n − 1) → P(n)$$
to derive P(n).
1. conclude on the basis of the principle of mathematical induction that $P(n)$ is true for all $n ≥ b$.


---
## Recurrence
- Iterating a recurrence 
  - bottom up or top down p

- prove by induction, complexity, ...


---
## Counting

- sum rule and product rule 
- Inclusion-Exclusion Principle 
- Pigeonhole Principle
- 
- ***Theorem***    
  - If N is a positive integer and k is an integer with $1 ≤ k ≤ n$, then there are  
$$P(n, k) = n(n − 1)(n − 2)· · ·(n − k + 1)$$
k-element permutations with n distinct elements. 
- $P(n, 3) = 3! · C(n, 3)$ 
- Pascal’s Triangle, Identity 
- The Binomial Theorem, Trinomial
- ***Definition*** 
  - An r -combination with repetition allowed, or a multiset of size r, chosen from a set of n elements, is an unordered selection of elements with repetition allowed.    
  - ***Example*** Find # multisets of size 17 from the set {1, 2, 3}.   
This is equivalent to finding the # nonnegative solutions to $x1 + x2 + x3 = 17$.  

- Solving linear (non-)homogeneous recurrence relation 
- Combinatorial proof 
- Generating function

---
## Binary Relations
- Properties of relations 
- Representing relations 
- Closures on relations 
- Equivalence relation
  - ***Definition*** A relation R on a set A is called an equivalence relation if it is reflexive, ***symmetric***, and transitive.
- Partial ordering
  - ***Definition*** A relation R on a set A is called a partial ordering if it is reflexive, ***antisymmetric***, and transitive.

---
## Graphs & Trees 
- connected graph, simple graph, planar graph,bipartite graph, complete graph, special graphs ( $K_n$, $K_{m,n}$, $C_n$, $W_n$, $Q_n$) 
- Euler circuit, Hamilton circuit
- shortest path, m-ary tree, tree traversal, isomophism, chromatic number, spanning tree ...
