// js/config.mjs
// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)

export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0, 
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4, 
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5, 
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6, 
        CELL_STATE_FLATTENED_OFFSET: 0x7,
    },
    CallFrame: {
        CALLEE_OFFSET: 0x8,
        ARG_COUNT_OFFSET: 0x10,
        THIS_VALUE_OFFSET: 0x18,
        ARGUMENTS_POINTER_OFFSET: 0x28
    },
    Structure: {
        CELL_SPECIFIC_FLAGS_OFFSET: 0x8,
        TYPE_INFO_TYPE_OFFSET: 0x9,
        TYPE_INFO_MORE_FLAGS_OFFSET: 0xA,
        TYPE_INFO_INLINE_FLAGS_OFFSET: 0xC,
        AGGREGATED_FLAGS_OFFSET: 0x10,
        VIRTUAL_PUT_OFFSET: 0x18,
        PROPERTY_STORAGE_CAPACITY_OFFSET: 0x18,
        PROPERTY_TABLE_OFFSET: 0x20,
        GLOBAL_OBJECT_OFFSET: 0x28,
        PROTOTYPE_OFFSET: 0x30,
        CACHED_OWN_KEYS_OFFSET: 0x48,
        CLASS_INFO_OFFSET: 0x50,
    },
    JSObject: {
        BUTTERFLY_OFFSET: 0x10,
    },
    JSFunction: {
        EXECUTABLE_OFFSET: 0x18,
        SCOPE_OFFSET: 0x20,
    },
    JSCallee: { 
        GLOBAL_OBJECT_OFFSET: 0x10,
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18,
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20,
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,
        KnownStructureIDs: {
            JSString_STRUCTURE_ID: null,
            ArrayBuffer_STRUCTURE_ID: 2,
            JSArray_STRUCTURE_ID: null,
            JSObject_Simple_STRUCTURE_ID: null
        }
    },
    ArrayBufferView: {
        STRUCTURE_ID_OFFSET: 0x00,
        FLAGS_OFFSET: 0x04,
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08,
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,
        M_VECTOR_OFFSET: 0x10,
        M_LENGTH_OFFSET: 0x18,
        M_MODE_OFFSET: 0x1C
    },
    ArrayBufferContents: {
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8,
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10,
        SHARED_ARRAY_BUFFER_CONTENTS_IMPL_PTR_OFFSET: 0x20,
        IS_SHARED_FLAG_OFFSET: 0x40,
        RAW_DATA_POINTER_FIELD_CANDIDATE_OFFSET: 0x5C,
        PINNING_FLAG_OFFSET: 0x5D,
    },
    VM: {
        TOP_CALL_FRAME_OFFSET: 0x9E98,
    },
};

export const WEBKIT_LIBRARY_INFO = {
    NAME: "libSceNKWebKit.sprx",
    FUNCTION_OFFSETS: {
        "JSC::JSFunction::create": "0x58A1D0",
        "JSC::InternalFunction::createSubclassStructure": "0xA86580",
        "WTF::StringImpl::destroy": "0x10AA800",
        "bmalloc::Scavenger::schedule": "0x2EBDB0",
        "WebCore::JSLocation::createPrototype": "0xD2E30",
        "WebCore::cacheDOMStructure": "0x740F30",
        "mprotect_plt_stub": "0x1A08",
        "JSC::JSWithScope::create": "0x9D6990",
        "JSC::JSObject::putByIndex": "0x1EB3B00",
        "JSC::JSInternalPromise::create": "0x112BB00",
        "JSC::JSInternalPromise::then": "0x1BC2D70",
        "JSC::loadAndEvaluateModule": "0xFC2900",
        "JSC::ArrayBuffer::create_from_arraybuffer_ref": "0x170A490",
        "JSC::ArrayBuffer::create_from_contents": "0x10E5320",
        "JSC::SymbolObject::finishCreation": "0x102C8F0",
        "JSC::StructureCache::emptyStructureForPrototypeFromBaseStructure": "0xCCF870",
        "JSC::JSObject::put": "0xBD68B0",
        "JSC::Structure::Structure_constructor": "0x1638A50",
        "WTF::fastMalloc": "0x1271810",
        "WTF::fastFree": "0x230C7D0",
        "JSValueIsSymbol": "0x126D940",
        "JSC::JSArray::getOwnPropertySlot": "0x2322630",
        "JSC::JSGlobalObject::visitChildren_JSCell": "0x1A5F740",
        "JSC::JSCallee::JSCallee_constructor": "0x2038D50",
        "gadget_lea_rax_rdi_plus_20_ret": "0x58B860",
        "JSC::throwConstructorCannotBeCalledAsFunctionTypeError": "0x112BBC0",
    },
    DATA_OFFSETS: {
        "JSC::JSArrayBufferView::s_info": "0x3AE5040",
        "JSC::DebuggerScope::s_info": "0x3AD5670",
        "JSC::Symbols::Uint32ArrayPrivateName": "0x3CC7968",
        "JSC::Symbols::Float32ArrayPrivateName": "0x3CC7990",
        "JSC::Symbols::Float64ArrayPrivateName": "0x3CC79B8",
        "JSC::Symbols::execPrivateName": "0x3CC7A30",
    }
};
