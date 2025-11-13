// js/utils.bundle.mjs

// --- Início de dom_elements.mjs (simplificado) ---
// Cache foi removido para simplicidade, pois 'document' está sempre disponível.
export function getElementById(id) {
    return document.getElementById(id);
}

// --- Início de logger.mjs ---
export function logToDiv(divId, message, type = 'info', funcName = '') {
    // Usa a função getElementById definida acima
    const outputDiv = getElementById(divId); 
    if (!outputDiv) {
        console.error(`Log target div "${divId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool'].includes(type) ? type : 'info';

        if(outputDiv.innerHTML.length > 600000){ 
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">[${new Date().toLocaleTimeString()}] [Log Truncado...]</span>\n` + lastPart;
        }

        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch(e) { 
        console.error(`Error in logToDiv for ${divId}:`, e, "Original message:", message); 
        if (outputDiv) outputDiv.innerHTML += `[${new Date().toLocaleTimeString()}] [LOGGING ERROR] ${String(e)}\n`; 
    }
}

// --- Início de utils.mjs ---
export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        this._isAdvancedInt64 = true;
        let buffer = new Uint32Array(2);
        
        let is_one_arg = false;
        if (arguments.length === 1) { is_one_arg = true; }
        if (arguments.length === 0) { 
            low = 0; high = 0; is_one_arg = false; 
        }

        if (!is_one_arg) {
            if (typeof (low) !== 'number' || typeof (high) !== 'number') {
                if (low instanceof AdvancedInt64 && high === undefined) {
                    buffer[0] = low.low();
                    buffer[1] = low.high();
                    this.buffer = buffer;
                    return;
                }
                throw TypeError('low/high must be numbers or single AdvancedInt64 argument');
            }
        }
        
        const check_range = (x) => Number.isInteger(x) && x >= 0 && x <= 0xFFFFFFFF;

        if (is_one_arg) {
            if (typeof (low) === 'number') {
                if (!Number.isSafeInteger(low)) { throw TypeError('number arg must be a safe integer'); }
                buffer[0] = low & 0xFFFFFFFF;
                buffer[1] = Math.floor(low / (0xFFFFFFFF + 1));
            } else if (typeof (low) === 'string') {
                let str = low;
                if (str.startsWith('0x')) { str = str.slice(2); }
                if (str.length > 16) { throw RangeError('AdvancedInt64 string input too long'); }
                str = str.padStart(16, '0');
                const highStr = str.substring(0, 8);
                const lowStr = str.substring(8, 16);
                buffer[1] = parseInt(highStr, 16);
                buffer[0] = parseInt(lowStr, 16);
            } else if (low instanceof AdvancedInt64) {
                 buffer[0] = low.low();
                 buffer[1] = low.high();
            } else {
                throw TypeError('single arg must be number, hex string or AdvancedInt64');
            }
        } else {
            if (!check_range(low) || !check_range(high)) {
                throw RangeError('low/high must be uint32 numbers');
            }
            buffer[0] = low;
            buffer[1] = high;
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    equals(other) {
        if (!(other instanceof AdvancedInt64)) { return false; }
        return this.low() === other.low() && this.high() === other.high();
    }
    
    static Zero = new AdvancedInt64(0,0);

    toString(hex = false) {
        if (!hex) {
            if (this.high() === 0) return String(this.low());
            return `(H:0x${this.high().toString(16)}, L:0x${this.low().toString(16)})`;
        }
        return '0x' + this.high().toString(16).padStart(8, '0') + '_' + this.low().toString(16).padStart(8, '0');
    }
    
    toNumber() {
        return this.high() * (0xFFFFFFFF + 1) + this.low();
    }

    add(val) {
        if (!(val instanceof AdvancedInt64)) { val = new AdvancedInt64(val); }
        const a = (BigInt(this.high()) << 32n) | BigInt(this.low());
        const b = (BigInt(val.high()) << 32n) | BigInt(val.low());
        const result = a + b;
        const newHigh = Number((result >> 32n) & 0xFFFFFFFFn);
        const newLow = Number(result & 0xFFFFFFFFn);
        return new AdvancedInt64(newLow, newHigh);
    }

    sub(val) {
        if (!(val instanceof AdvancedInt64)) { val = new AdvancedInt64(val); }
        const a = (BigInt(this.high()) << 32n) | BigInt(this.low());
        const b = (BigInt(val.high()) << 32n) | BigInt(val.low());
        const result = a - b;
        const newHigh = Number((result >> 32n) & 0xFFFFFFFFn);
        const newLow = Number(result & 0xFFFFFFFFn);
        return new AdvancedInt64(newLow, newHigh);
    }

    and(val) {
        if (!(val instanceof AdvancedInt64)) { val = new AdvancedInt64(val); }
        const newLow = this.low() & val.low();
        const newHigh = this.high() & val.high();
        return new AdvancedInt64(newLow >>> 0, newHigh >>> 0);
    }

    not() {
        const newLow = ~this.low() >>> 0;
        const newHigh = ~this.high() >>> 0;
        return new AdvancedInt64(newLow, newHigh);
    }
}

export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

export async function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(val, bits = 32) {
    if (isAdvancedInt64Object(val)) {
        return val.toString(true);
    }
    if (typeof val !== 'number') {
        return `NonNumeric(${typeof val}:${String(val)})`;
    }
    if (isNaN(val)) {
        return 'ValIsNaN';
    }
    let hexStr;
    if (val < 0) {
        if (bits === 32) { hexStr = (val >>> 0).toString(16); }
        else if (bits === 16) { hexStr = ((val & 0xFFFF) >>> 0).toString(16); }
        else if (bits === 8) { hexStr = ((val & 0xFF) >>> 0).toString(16); }
        else { hexStr = val.toString(16); }
    } else {
        hexStr = val.toString(16);
    }
    const numChars = Math.ceil(bits / 4);
    return '0x' + hexStr.padStart(numChars, '0');
}

export function stringToAdvancedInt64Array(str, nullTerminate = true) {
    // ... (função mantida como estava)
    if (typeof str !== 'string') {
        console.error("Input to stringToAdvancedInt64Array must be a string.");
        return [];
    }
    const result = [];
    const charsPerAdv64 = 4;
    for (let i = 0; i < str.length; i += charsPerAdv64) {
        let low = 0;
        let high = 0;
        const char1_code = str.charCodeAt(i);
        const char2_code = (i + 1 < str.length) ? str.charCodeAt(i + 1) : 0;
        const char3_code = (i + 2 < str.length) ? str.charCodeAt(i + 2) : 0;
        const char4_code = (i + 3 < str.length) ? str.charCodeAt(i + 3) : 0;
        low = (char2_code << 16) | char1_code;
        high = (char4_code << 16) | char3_code;
        result.push(new AdvancedInt64(low, high));
        if (char4_code === 0 && i + 3 < str.length && nullTerminate) break; 
        if (char3_code === 0 && i + 2 < str.length && char4_code === 0 && nullTerminate) break;
        if (char2_code === 0 && i + 1 < str.length && char3_code === 0 && char4_code === 0 && nullTerminate) break;
    }
    if (nullTerminate && (str.length % charsPerAdv64 !== 0 || str.length === 0)) {
         if (str.length === 0) result.push(AdvancedInt64.Zero);
    }
    return result;
}

export function advancedInt64ArrayToString(arr) {
    // ... (função mantida como estava)
    let str = "";
    if (!Array.isArray(arr)) return "InputIsNotArray";
    for (const adv64 of arr) {
        if (!isAdvancedInt64Object(adv64)) continue;
        const low = adv64.low();
        const high = adv64.high();
        const char1_code = low & 0xFFFF;
        const char2_code = (low >>> 16) & 0xFFFF;
        const char3_code = high & 0xFFFF;
        const char4_code = (high >>> 16) & 0xFFFF;
        if (char1_code === 0) break;
        str += String.fromCharCode(char1_code);
        if (char2_code === 0) break;
        str += String.fromCharCode(char2_code);
        if (char3_code === 0) break;
        str += String.fromCharCode(char3_code);
        if (char4_code === 0) break;
        str += String.fromCharCode(char4_code);
    }
    return str;
}

export function doubleToBigInt(d) {
    const buffer = new ArrayBuffer(8);
    const float64View = new Float64Array(buffer);
    const bigIntView = new BigUint64Array(buffer);
    float64View[0] = d;
    return bigIntView[0];
}

export function bigIntToDouble(b) {
    const buffer = new ArrayBuffer(8);
    const bigIntView = new BigUint64Array(buffer);
    const float64View = new Float64Array(buffer);
    bigIntView[0] = b;
    return float64View[0];
}
