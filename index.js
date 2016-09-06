const isBrowser = typeof window !== 'undefined';
const globalObject = isBrowser ? window : global;
const grabCryptographicallyStrongBytes = (()=>{
    // Our enviroment isn't likely to change,
    // so we create different functions depending on context to avoid unnecessary branching
    if (isBrowser) {
        return n=>{
            return globalObject.crypto.getRandomValues(new Uint8Array(n));
        };
    } else {
        const crypto = require('crypto');
        return n =>{
            // Buffer returned by crypto is subclass of Uint8Array
            // so cast isn't neccesary
            return crypto.randomBytes(n);
        };
    }
})();


// Based on reference implementation of XorShift algorithm
// 128 bits of state, isn't cryptographically secure
const XOR_SHIFT_INTERNAL_STATE = Symbol('XorShift internal state');
class XorShift {
    constructor(x, y, z, w) {
        this[XOR_SHIFT_INTERNAL_STATE] = new Uint32Array([x, y, z, w]);
    }

    // Convenient method to create new instance without specyfing initial state
    static withStrongSeed() {
        const [x, y, z, w] = new Uint32Array(grabCryptographicallyStrongBytes(4*(Uint32Array.BYTES_PER_ELEMENT)).buffer);
        return new this(x, y, z, w);
    }

    // Create clone with the same internal state
    clone() {
        return new this.constructor(...this[XOR_SHIFT_INTERNAL_STATE]);
    }

    // Returns 31 bit positive integer
    getNextValue() {
        let t = this._x;
        t ^= t << 11;
        t ^= t >> 8;
        [this._x, this._y, this._z] = [this._y, this._z, this._w];
        this._w ^= this._w >> 19;
        this._w ^= t;
        return this._w;
    }

    get MAX_VALUE() {
        return Math.pow(2,31);
    }

    // Convenient alternative for Math.random();
    random() {
        return this.getNextValue()/this.MAX_VALUE;
    }

    // instances of XorShift are iterators and iterables at once
    next() {
        return {
            value: this.getNextValue(),
            done: false
        };
    }

    [Symbol.iterator]() {
        return this;
    }

    // Short getters/setters should be inlined by JIT
    get _x() {
        return this[XOR_SHIFT_INTERNAL_STATE][0];
    }
    set _x(val) {
        return this[XOR_SHIFT_INTERNAL_STATE][0] = val;
    }
    get _y() {
        return this[XOR_SHIFT_INTERNAL_STATE][1];
    }
    set _y(val) {
        return this[XOR_SHIFT_INTERNAL_STATE][1] = val;
    }
    get _z() {
        return this[XOR_SHIFT_INTERNAL_STATE][2];
    }
    set _z(val) {
        return this[XOR_SHIFT_INTERNAL_STATE][2] = val;
    }
    get _w() {
        return this[XOR_SHIFT_INTERNAL_STATE][3];
    }
    set _w(val) {
        return this[XOR_SHIFT_INTERNAL_STATE][3] = val;
    }

}


const SEQUENCE = Symbol('Private property containing Sequencer sequence');
const PRNG = Symbol('Private property containing Sequencer internal pseudorandom number generator');

class AbstractSequencer {
    constructor(sequence, prng=Math) {
        this[SEQUENCE] = [...sequence];
        if (this[SEQUENCE].length === 0) {
            throw new TypeError('Can\'t iterate over empty collection');
        }
        this[PRNG] = prng;
    }

    next() {
        return {
            value: this.getNextValue(),
            done: false
        }
    }

    [Symbol.iterator]() {
        return this;
    }

    get size() {
        return this[SEQUENCE].length;
    }
}


class NaiveSequencer extends AbstractSequencer {
    getNextValue() {
        return this[SEQUENCE][Math.floor(this.size*this[PRNG].random())];
    }
}

const RATE =  Symbol('Private property containing rate of "flip"');
const FLIP_FUNCTION = Symbol('Private property containing ');
const LAST_ENTRIES = Symbol('Table containing last n entries');
const LAST_ENTRIES_COUNT = Symbol('Max length for entries');

// Sequencer that reduce chance of (1,1) cases
// Useful for output seen by user
// Empirical evidence suggest optimal values: size ** rate == lastEntriesCount
class DeduplicationSequencer extends AbstractSequencer {
    constructor(seq, prng, options) {
        const {
            rate=0.5,
            lastEntriesCount=5,
            flip=(e=>e)
        } = options;
        super(seq, prng);
        if(lastEntriesCount >= this.size) {
            throw new TypeError(`Too big lastEntriesCount specified: ${lastEntriesCount} for sequence of length ${this.size}`);
        }
        if (rate >= 1 || rate < 0) {
            throw new TypeError
        }
        this[RATE] = rate;
        this[LAST_ENTRIES] = [];
        this[LAST_ENTRIES_COUNT] = lastEntriesCount;
        this[FLIP_FUNCTION] = flip;
    }

    getNextValue() {
        // Actually, it can be replaced by tail recursion - but we risk overflowing stack and bad performance
        var position, contains;
        const flipFunction = this[FLIP_FUNCTION];
        const flipRate = this[RATE];
        const lastEntries = this[LAST_ENTRIES];
        do {
            position = Math.floor(this.size*this[PRNG].random());
            contains = this[LAST_ENTRIES].contains(position); // Search over last few positions (5 elements)
        } while(contains && flipFunction(this[PRNG].random(), val, lastEntries) < flipRate);
        lastEntries.push(position);
        if(lastEntries.length > this[LAST_ENTRIES_COUNT]) {
            lastEntries.shift();
        }
        return this[SEQUENCE][position];
    }
}





module.exports = {
    XorShift,
    AbstractSequencer,
    NaiveSequencer,
    DeduplicationSequencer
};