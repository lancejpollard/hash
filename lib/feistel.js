'use strict'

// https://github.com/stepanzin/Information-security/blob/master/js/src/feistel.js
const randomHalfByteKey = () => {
  let text = ''
  let q = 0
  for (let i = 0; i < 4; i++) {
    const char = (Math.random() >= 0.5) ? 1 : 0
    if (char) {
      q++
    }
    text += char
  }
  if (q % 2 === 0) {
    return text
  }

  return randomHalfByteKey()
}

const strToBin = str => {
  return str.split('').map(e => {
    const bin = e.charCodeAt(0).toString(2)
    return '0'.repeat(8 - bin.length) + bin
  }).join('')
}

const binToStr = bin => {
  let i = 0
  const str = []
  do {
    str.push(String.fromCharCode(parseInt(bin.slice(i, i += 8), 2)))
  }
  while (i !== bin.length)
  return str.join('')
}

function xor(a, b) {
  return a.split('').map((e, i) => e ^ b[i]).join('')
}

String.prototype.rotate = function(n) {
  return this.slice(n, this.length).concat(this.slice(0, n));
}

class Feistel {
  constructor(text, r = 10, k) {
    this.t = text
    this.r = r
    this.c = ''
    this.d = ''
    this.k = k
    this.keyArr = [k]
  }

  traverseTree(tree, visitor) {
    if (Array.isArray(tree)) {
      for (let i = 0; i < tree.length; i++) {
        this.traverseTree(tree[i], visitor)
      }
    }
    else {
      visitor(tree)
    }
  }

  crypt() {
    const bitSequence = strToBin(this.t)
    let char = []
    let i = 0
    do {
      char.push(bitSequence.slice(i, i += 8))
    } while (i < bitSequence.length)

    for (let q = 0; q < this.r - 1; q++) {
      char = char.map(e => {
        let left = e.slice(0, 4)
        let right = e.slice(4, 8)

        const temp = xor(xor(left, this.keyArr[q]), right)
        right = left
        left = temp

        return left.concat(right)
      })
      const newkey = this.keyArr[this.keyArr.length - 1].rotate(1)
      this.keyArr.push(newkey)
    }

    char = char.map(e => {
      const left = e.slice(0, 4)
      let right = e.slice(4, 8)
      right = xor(xor(left, this.keyArr[this.keyArr.length - 1]), right)
      return left.concat(right)
    })
    this.c = binToStr(char.join(''))

    return {
      key: this.k,
      rounds: this.r,
      result: this.c,
    }
  }

  decrypt() {
    const bitSequence = strToBin(this.c)
    let char = []
    let i = 0
    do {
      char.push(bitSequence.slice(i, i += 8))
    } while (i < bitSequence.length)

    for (let q = this.r - 1; q > 0; q--) {
      char = char.map(e => {
        let left = e.slice(0, 4)
        let right = e.slice(4, 8)

        const temp = xor(xor(right, this.keyArr[q]), left)
        left = right
        right = temp

        return left.concat(right)
      })
    }

    char = char.map(e => {
      let left = e.slice(0, 4)
      const right = e.slice(4, 8)
      left = xor(xor(right, this.keyArr[0]), left)
      return left.concat(right)
    })

    this.c = binToStr(char.join(''))

    return {
      key: this.k,
      rounds: this.r,
      result: this.c,
    }
  }
}

// const rounds = randomInt(2, 16)
const cipher = new Feistel('run the jewel', 6, randomHalfByteKey())
const q = cipher.crypt()
const p = cipher.decrypt()
console.log(JSON.stringify(q.result))
console.log(JSON.stringify(p.result))
