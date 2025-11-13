// js/utils.bundle.mjs (Mesma base, com adições mínimas para ROP)

export function getElementById(id) {
    return document.getElementById(id);
}

export function logToDiv(divId, message, type = 'info', funcName = '') {
    const outputDiv = getElementById(divId); 
    if (!outputDiv) {
        console.error(`Log target div "${divId}" not found. Message: ${message}`);
        return;
    }
    try {
        const timestamp = `[${new Date().toLocaleTimeString()}]`;
        const prefix = funcName ? `[${funcName}] ` : '';
        const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool', 'rop'].includes(type) ? type : 'info';  // Adicionado 'rop'

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

export class AdvancedInt64 {
    // Mesma implementação original...
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
