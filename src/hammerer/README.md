## Hammerer
This modules contains the logic for performing the Rowhammer attack.

This module provides two different hammering strategies: `Blacksmith` and `Dummy`.
These strategies allow testing the resilience of DRAM to Rowhammer attacks.

## Modules

- `blacksmith`: Implements the `Blacksmith` hammerer, which uses advanced hammering techniques.
- `dummy`: Implements the `Dummy` hammerer, which serves as a baseline or no-op hammerer.

## Traits

- `Hammering`: The main trait for hammering operations. Any hammerer must implement this trait
  to perform the hammering on a given victim.

## Types

- `HammerResult`: The result returned by hammering operations, defined in the `blacksmith` module.
- `HammerVictim`: A trait that represents the target memory being hammered.

License: MIT
