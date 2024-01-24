globalThis.clear = () => console.log('\x1Bc')

declare global {
    var clear: () => void
}

export { }