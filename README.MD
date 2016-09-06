# Sequencer

Create infinite-length sequences from your iterables

```javascript

const {
    XorShift,
    AbstractSequencer,
    NaiveSequencer,
    DeduplicationSequencer
} = require('infinite-sequencer');
const arr = [1,2,3,4,5,6];
const seq = new NaiveSequencer(arr);
while(true) {
   seq.next(); // {value: number, done: false}
}

```

## AbstractSequencer(sequence, prng)

Abstract class, provides methods `next` and getter `size`. Subclasses must implement method `getNextValue`, returning value.
* `sequence` must be an finite iterable
* `prng` must be either object with method `random`, returning number from 0 to 1. Default to `Math` builtin object.

## NaiveSequencer(sequence, prng)

Generates stream of random values from sequence.

## DeduplicationSequencer(sequence, prng, {rate, lastEntriesCount, flip})

Generates stream of random values. Drawing a value lowers chance of getting the same value in `lastEntriesCount` next items.

Optimized for human skewed sense of "randomness".

* `rate=0.5` - chance to redraw, compared to result of `flip`
* `flip(randomValue: Number, i: Int32, lastItemsPositions: Int32[])` - function to determine chances. Defaults to identity - `randomValue=>randomValue`.
* `lastEntriesCount=5` - determines number last elements to check.

