const PREC = {
  COMMENT: 0,
  ASSIGN: 1,         // Assignment operators
  RETURN: 1,         // return statement
  STATEMENT: 2,      // Statements
  OR: 2,             // ||
  AND: 3,            // &&
  BIT_OR: 4,         // |
  BIT_XOR: 5,        // ^
  BIT_AND: 6,        // &
  EQUALITY: 7,       // ==  !=
  REL: 8,            // <  <=  >  >=
  SHIFT: 9,          // <<  >>  >>>
  ADD: 10,           // +  -
  MULT: 11,          // *  /  %
  UNARY: 12,         // Unary operators like -a, !a
  COPY: 12,          // copy_expression
  MOVE: 12,          // move_expression
  CALL: 13,          // Function calls
  FIELD: 13,
  PARENS: 14,        // (Expression)
  ARRAY: 14,         // [Expression]
  PATH: 15,          // a::b
  PATH_SEGMENT: 16,  // a::b::c
};

module.exports = grammar({
  name: "abc",

  extras: $ => [
    $.comment,
    /\s/,  // Whitespace

  ],

  word: $ => $.identifier,

  rules: {
    // TODO: add the actual grammar rules


    // @ts-ignore
    program: $ => repeat($._toplevel_statement),

    _toplevel_statement: $ => choice(
      $.declaration,
      $.statement,
      $.file_name, 
      $.language,
      $.section_sep,
    ),

    type: $ => choice(
      'u8', 'i32', 'u32', 'i64', 'u64', 'f32', 'f64', 'bool', 'char', 'string', 'usize', "()", "any", "null_value", "u1",
    ),

    file_name: $ => token("# source binary: modules.abc"),

    language: $ => token(".language ECMAScript"),

    section_sep: $ => seq(
      token("# ===================="),
      choice(
        token("# LITERALS"), 
        token("# RECORDS"), 
        token("# METHODS"),
        token("# STRING"),
      )
    ),



    declaration: $ => choice(
      $.function_declaration,
    ),

    function_header: $ => prec.left(seq(
      'L_ESSlotNumberAnnotation:', 
      'u32', 
      'slotNumberIdx', 
      '{', 
      $.hexi, 
      '}',
      optional(
        seq(
          'L_ESConcurrentModuleRequestsAnnotation:', 
          'u32', 
          'concurrentModuleRequestIdx', 
          '{', 
          commaSep($.hexi), 
          '}'
        )
      ), 
      '.function',
      'any',
      choice(
        $.function_name_type1,
        field('name', $.dot_or_slash_separated_identifiers),
      ),
      '(',
      optional(field('parameters', $.parameters)),
      ')',
      '<',
      field('return_type', $.identifier),
      '>'
      //field('return_type', choice($.type, seq('(', ')') )),  
    )),

    parameters: $ => commaSep1($.parameter),

    parameter: $ => seq(
      field('type', $.type),

      field('name', $.identifier)
    ),

    function_body: $ => seq(
      '{',
      repeat(
        choice(
          $.declaration,
          $.statement,
        )
      ),

      '}',
    ),

    function_declaration: $ => prec.left(seq(
      $.function_header,
      optional($.function_body),
    )),

    function_name_type1: $ => prec(1, seq(
      '&',optional('@'),
      field('file_path', $.file_path),
      '&',
      optional($.version),
      '.',
      field('name', choice($.identifier, $.temp_name)),

    )),

    file_path: $ => $.dot_or_slash_separated_identifiers,

    dot_or_slash_separated_identifiers: $ => prec.left(seq(
      $.identifier,                   // 起始标识符
      repeat(seq(choice('.', '/', '@'), $.identifier))  // 后续以.或/分隔的标识符
    )),

    temp_name: $ => seq(
      '#',
      field("scope_name", choice($.scope, $.deci)),
      '#',
      optional(field("function_name", $.identifier)),
      optional(seq('^', field('repeat_index', $.hexi_without_prefix))),
    ),
    hexi_without_prefix: $ => /[0-9a-fA-F]+/,
    // scope: $ => /[^#]*/,
    scope: $ => seq(
      repeat1($.scope_name),
      $.scope_type
    ),
    scope_name: $ => seq(
      $.scope_type,
      // field("scope_type", optional(choice('~', '&'))),
      optional(choice($.identifier, $.scope_id)),
      optional(seq('^', field('repeat_index', $.hexi_without_prefix)))
    ),
    
    scope_type: $ => choice('~', '&', '>', '<', '=', '*', '%'),
    scope_id: $ => seq(
      '@',
      field("scope_id", choice($.deci, 'a', 'b', 'c', 'd', 'e', 'f')),
    ),

    statement: $ => prec(PREC.STATEMENT, choice(
      $.declaration,
      $.sta_statement,
      $.lda_statement,
      $.ldastr_statement,
      $.ldundefiened_statement,
      $.ldnull_statement,
      $.ldtrue_statement,
      $.ldfalse_statement,
      $.ldlexvar_statement,
      $.ldlocalmodulevar_statement,
      $.ldai_statement,
      $.fldai_statement,
      $.ldobjbyname_statement,
      $.ldobjbyvalue_statement,
      $.ldexternalmodulevar_statement,
      $.ldhole_statement,
      $.ldglobal_statement,
      $.ldsuperbyname_statement,
      $.call_statement,
      $.callthis0_statement,
      $.callthis1_statement,
      $.callthis2_statement,
      $.callthis3_statement,
      $.callthisrange_statement,
      $.supercallthisrange_statement,
      $.callrange_statement,
      $.callarg1_statement,
      $.callargs2_statement,
      $.callargs3_statement,
      $.callruntime_statement,
      $.getiterator_statement,
      $.definefunc_statement,
      $.definemethod_statement,
      $.definefieldbyname_statement,
      $.definefieldbyvalue_statement,
      $.defineclass_statement,
      $.mov_statement,
      $.tryldglobalbyname_statement,
      $.stlexvar_statement,
      $.stmodulevar_statement,
      $.stownbyindex_statement,
      $.stownbyname_statement,
      $.stobjbyname_statement,
      $.stobjbyvalue_statement,
      $.returnundefined_statement,
      $.return_statement,
      $.new_array_statement,
      $.newobjrange_statement,
      $.newenv_statement,
      $.poplexenv_statement,
      $.add_statement,
      $.dec_statement, 
      $.sub_statement,
      $.mul_statement,
      $.div_statement,
      $.mod_statement,
      $.eq_statement,
      $.noteq_statement,
      $.less_statement,
      $.lesseq_statement,
      $.greater_statement,
      $.greatereq_statement,
      $.and_statement,
      $.or_statement,
      $.xor_statement,
      $.tonumeric_statement,
      $.ifhole_statement,
      $.isfalse_statement,
      $.istrue_statement,
      $.strictnoteq_statement,
      $.stricteq_statement,
      $.inc_statement,
      $.copyrestargs_statement,
      $.supercallspread_statement,
      $.throwcallwrong_statement,
      $.throwifnotobject_statement,
      $.asyncfunctionenter_statement,
      $.neg_statement,
      $.asyncfunctionawaituncaught_statement,
      $.asyncfunctionreject_statement,
      $.asyncfunctionresolve_statement,
      $.suspendgenerator_statement,
      $.resumegenerator_statement,
      $.getresumemode_statement,
      $.createemptyarray_statement,
      $.createobjectwithbuffer_statement,
      $.createemptyobject_statement,
      $.isin_statement,
      $.jnez_statement,
      $.jeqz_statement,
      $.jmp_statement,
      $.module_record,
      $.module_literal,
      $.scope_literal,
      $.getmodulenamespace_statement,
      $.checkholebyname_statement,
      $.label_statement,
      $.throw_statement,
      $.catch_statement,
      $.typeof_statement,
      $.instanceof_statement,
      $.definegettersetter_statement,
      $.dynamic_import,
      )),

    //解析字节码的record部分
    module_record: $ => seq(
      '.record',
      '&',optional('@'), $.path, '&',
      optional($.version),
      '{',
      repeat($.field),
      '}'
    ),
    version: $ => seq(
      $.deci,
      '.',
      $.deci,
      '.',
      $.deci,
    ),
    field: $ => seq(
      $.type,
      $.field_name,
      '=',
      $.hexi,
      optional(';')
    ),
    field_name: $ => /[a-zA-Z0-9_@./]+/,


    //解析字节码的literal部分
    module_literal: $ => seq(
      $.deci,
      field('idnumber', $.hexi),
      '{',
      field("moduletag_number", $.deci),
      '[',
      $.module_request_array,
      field("module_tag", repeat($.module_tag)),
      ']}'
    ),

    // MODULE_REQUEST_ARRAY 部分
    module_request_array: $ => seq(
      'MODULE_REQUEST_ARRAY:',
      '{',
      repeat($.module_request_item),
      '};'
    ),
    // 单个模块请求项
    module_request_item: $ => seq(
      $.deci,
      ':',
      $.module_reference,
      ','
    ),
    // ModuleTag 声明
    module_tag: $ => seq(
      'ModuleTag:',
      choice(
        $.regular_import_type,
        $.indirect_import_type,
        $.namespace_import_tag,
        $.local_export_tag,
        $.star_export_tag,
      ),
      ';'
    ),
    scope_literal: $ => seq(
      $.deci,
      field('idnumber', $.hexi),
      optional(seq('{',
      field("scope_tag_number", $.deci),
      '[',
      field("scope_tag", repeat($.scope_tag)),
      ']}')),
    ),
    scope_tag: $ => seq(
      choice('string:', 'i32:', 'u1:', 'f64:', 'null_value:', 'method:', 'method_affiliate:', 'accessor:', 'lit_offset:'),
      field(
        'value', 
        choice(
          $.string_literal,
          $.deci,
          $.hexi,
          $.float,
          $.temp_name,
          $.identifier,
          $.scientific,
        ),
      ),
      ','
    ),
    regular_import_type: $ => seq(
      'REGULAR_IMPORT',
      ',',
      'local_name:', $.identifier,
      ',',
      'import_name:', $.identifier,
      ',',
      'module_request:', $.module_reference
    ),
    indirect_import_type: $ => seq(
      'INDIRECT_EXPORT',
      ',',
      'export_name:', $.identifier,
      ',',
      'import_name:', $.identifier,
      ',',
      'module_request:', $.module_reference
    ),

    namespace_import_tag: $ => seq(
      'NAMESPACE_IMPORT',
      ',',
      'local_name:', $.identifier,
      ',',
      'module_request:', $.module_reference
    ),

    local_export_tag: $ => seq(
      'LOCAL_EXPORT',
      ',',
      'local_name:', optional('*'), $.identifier, optional('*'),
      ',',
      'export_name:', $.identifier,
    ),

    star_export_tag: $ => seq(
      'STAR_EXPORT',
      ',',
      'module_request:', $.module_reference
    ),


    tag_type: $ => choice(
      'REGULAR_IMPORT',
      'LOCAL_EXPORT'
    ),

    module_reference: $ => choice(
      $.package_reference,
      $.ohos_reference,
      $.hms_reference,
      $.bundle_reference,
      $.normalized_reference,
      $.native_reference,
    ),
    package_reference: $ => seq(
      '@package:',
      $.file_path,
      optional($.end_number)
    ),
    ohos_reference: $ => seq(
      '@ohos:',
      $.file_path,
      optional($.end_number)
    ),
    hms_reference: $ => seq(
      '@hms:',
      $.file_path,
      optional($.end_number)
    ),
    native_reference: $ => seq(
      '@native:',
      $.file_path,
      optional($.end_number)
    ),
    bundle_reference: $ => seq(
      '@bundle:',
      $.file_path,
      optional($.end_number)
    ),
    normalized_reference: $ => seq(
      choice('@normalized:N&&&', '@normalized:Y&&&'),
      optional('@'),
      $.file_path,
      '&',
      optional($.end_number)
    ),
    path: $ => /[a-zA-Z0-9_.+\/-]+/,
    sta_statement: $ => seq(
      'sta',
      field('register', $.identifier),
    ),

    lda_statement: $ => seq(
      'lda',
      field('register', $.identifier),
    ),


    ldastr_statement: $ => seq(
      'lda.str',
      field(
        'string',
        $.string,
      ),
    ),

    ldundefiened_statement: $ => 'ldundefined',
    ldnull_statement: $ => "ldnull",
    ldtrue_statement: $ => 'ldtrue',
    ldfalse_statement: $ => 'ldfalse',

    ldlexvar_statement: $ => seq(
      'ldlexvar',
      field('lexi_env', $.hexi),
      ',',
      field('slot', $.hexi),
    ),

    ldlocalmodulevar_statement: $ => seq(
      'ldlocalmodulevar',
      field('slot', $.hexi),
    ),

    

    ldai_statement: $ => seq(
      'ldai',
      field('imm', $.hexi),
    ),
    fldai_statement: $ => seq(
      'fldai',
      field('imm', $.scientific),
    ),

    ldobjbyname_statement: $ => seq(
      'ldobjbyname',
      field('reserve', $.hexi),
      ',',
      '"',
      field('object', $.identifier,),
      '"'
    ),

    ldobjbyvalue_statement: $ => seq(
      'ldobjbyvalue',
      field('reserve', $.hexi),
      ',',
      field('object', $.identifier),
    ),

    ldexternalmodulevar_statement: $ => seq(
      'ldexternalmodulevar',
      field('slot', $.hexi),
    ),

    ldhole_statement: $ => "ldhole",

    ldglobal_statement: $ => "ldglobal",

    ldsuperbyname_statement: $ => seq(
      'ldsuperbyname',      
      field('reserve', $.hexi),
      ',',
      '"',
      field('name', $.identifier),
      '"',
    ),

    call_statement: $ => seq(
      'callarg0',
      field('reserve', $.hexi),
    ),

    callthis0_statement: $ => seq(
      'callthis0',
      field('reserve', $.hexi),
      ',',
      field('this', $.identifier),
    ),
    callthis1_statement: $ => seq(
      'callthis1',
      field('reserve', $.hexi),
      ',',
      field('this', $.identifier),
      ',',
      field('arg1', $.identifier),
    ),

    callthis2_statement: $ => seq(
      'callthis2',
      field('reserve', $.hexi),
      ',',
      field('this', $.identifier),
      ',',
      field('arg1', $.identifier),
      ',',
      field('arg2', $.identifier),
    ),

    callthis3_statement: $ => seq(
      'callthis3',
      field('reserve', $.hexi),
      ',',
      field('this', $.identifier),
      ',',
      field('arg1', $.identifier),
      ',',
      field('arg2', $.identifier),
      ',',
      field('arg3', $.identifier),
    ),

    callthisrange_statement: $ => seq(
      'callthisrange',
      field('reserve', $.hexi),
      ',',
      field('args_number', $.hexi),
      ',',
      field('arg_start', $.identifier),
    ),

    supercallthisrange_statement: $ => seq(
      'supercallthisrange',
      field('reserve', $.hexi),
      ',',
      field('args_number', $.hexi),
      ',',
      field('arg_start', $.identifier),
    ),

    callrange_statement: $ => seq(
      choice('callrange', 'wide.callrange'),
      field('reserve', $.hexi),
      ',',
      field('args_number', $.hexi),
      ',',
      field('arg_start', $.identifier),
    ),

    callarg1_statement: $ => seq(
      'callarg1',
      field('reserve', $.hexi),
      ',',
      field('arg1', $.identifier),
    ),

    callargs2_statement: $ => seq(
      'callargs2',
      field('reserve', $.hexi),
      ',',
      field('arg1', $.identifier),
      ',',
      field('arg2', $.identifier),
    ),

    callargs3_statement: $ => seq(
      'callargs3',
      field('reserve', $.hexi),
      ',',
      field('arg1', $.identifier),
      ',',
      field('arg2', $.identifier),
      ',',
      field('arg3', $.identifier),
    ),

    callruntime_statement: $ => seq(
      choice(
        'callruntime.supercallforwardallargs',
        'callruntime.notifyconcurrentresult',
      ),
      optional(field('arg', $.identifier)),
    ),

    getiterator_statement: $ => seq(
      'getiterator',
      field('reserve', $.hexi),
    ),

    mov_statement: $ => seq(
      'mov',
      field('v1', $.identifier),
      ',',
      field('v2', $.identifier),
    ),

    stlexvar_statement: $ => seq(
      'stlexvar',
      field('lexi_env', $.hexi),
      ',',
      field('slot', $.hexi),
    ),

    stmodulevar_statement: $ => seq(
      'stmodulevar',
      field('slot', $.hexi),
    ),

    stownbyindex_statement: $ => seq(
      'stownbyindex',
      field('reserve', $.hexi),
      ',',
      field('object', $.identifier),
      ',',
      field('index', $.hexi),
    ),

    stownbyname_statement: $ => seq(
      'stownbyname',
      field('reserve', $.hexi),
      ',',
      field('object', $.string),
      ',',
      field('name', $.identifier),
    ),

    stobjbyname_statement: $ => seq(
      'stobjbyname',
      field('reserve', $.hexi),
      ',',
      '"',
      field('field', $.identifier,),
      '"',
      ',',
      field('object', $.identifier),
    ),

    stobjbyvalue_statement: $ => seq(
      'stobjbyvalue',
      field('reserve', $.hexi),
      ',',
      field('object', $.identifier),
      ',',
      field('index', $.identifier),
    ),

    new_array_statement: $ => seq(
      'createarraywithbuffer',
      $.hexi,
      ',',
      $.literal,
    ),

    newobjrange_statement: $ => seq(
      'newobjrange',
      field('reserve', $.hexi), ',',
      field('param_num', $.hexi), ',',
      field('object', $.identifier),
    ),

    newenv_statement: $ => seq(
      'newlexenvwithname',
      field('slot_number', $.hexi),
      ',',
      $.literal,
    ),

    poplexenv_statement: $ => 'poplexenv',


    definefunc_statement: $ => seq(
      'definefunc',
      field('reserve', $.hexi), ',',
      $.method_decl,
      field('args_number', $.hexi),

    ),

    definemethod_statement: $ => seq(
      'definemethod ',
      field('reserve', $.hexi), ',',
      $.method_decl,
      field('args_number', $.hexi),
    ),

    definefieldbyname_statement: $ => seq(
      choice('definefieldbyname', 'definepropertybyname'),
      field('reserve', $.hexi), ',',
      field('field', $.string), ',',
      field('object', $.identifier),
    ),
    definefieldbyvalue_statement: $ => seq(
      'callruntime.definefieldbyvalue',
      field('reserve', $.hexi), ',',
      field('field', $.identifier), ',',
      field('object', $.identifier),
    ),

    defineclass_statement: $ => seq(
      'defineclasswithbuffer',
      field('reserve', $.hexi), ',',
      field('class_name', $.method_decl),
      $.literal,
      ',',
      field('formal_paranum', $.hexi),
      ',',
      field('super', $.identifier),
    ),

    definegettersetter_statement: $ => seq(
      'definegettersetterbyvalue',
      field('register1', $.identifier),
      ',',
      field('register2', $.identifier),
      ',',
      field('register3', $.identifier),
      ',',
      field('register4', $.identifier),
    ),

    method_decl: $ => seq(
      $.function_name_type1,
      ':(',
      commaSep1($.type),
      '),',
    ),

    ifhole_statement: $ => seq(
      'throw',
      '"',
      $.string,
      '"',
    ),

    istrue_statement: $ => seq(
      choice('istrue', 'callruntime.istrue'), 
      optional($.hexi)
    ),

    isfalse_statement: $ => seq(
      choice('isfalse', 'callruntime.isfalse'), 
      optional($.hexi)
    ),

    jeqz_statement: $ => seq(
      'jeqz',
      field('target', $.identifier),
    ),

    jnez_statement: $ => seq(
      'jnez',
      field('target', $.identifier),
    ),

    jmp_statement: $ => seq(
      'jmp',
      field('target', $.identifier),
    ),

    jmploop_statement: $ => seq(
      'jmp_loop',
      field('target', $.identifier),
    ),

    label_statement: $ => choice(
      $.jump_label,
      $.try_begin,
      $.try_end,
      $.handler_begin_label,
      $.handler_end_label,
    ),
    // jump_label: $ => seq(
    //   'jump_label_',
    //   field('index', $.deci),
    //   ':',
    // ),

    try_begin: $ => /try_begin_label_\d+:/,
    try_end: $ => /try_end_label_\d+:/,
    jump_label: $ => /jump_label_\d+:/,
    handler_begin_label: $ => /handler_begin_label_\d+_\d+:/,
    handler_end_label: $ => /handler_end_label_\d+_\d+:/,

    throw_statement: $ => "throw",

    single_label: $ => choice(
      /try_begin_label_\d+/, 
      /try_end_label_\d+/, 
      /handler_begin_label_\d+_\d+/, 
      /handler_end_label_\d+_\d+/,
    ),

    catch_statement: $ => seq(
      ".catchall",
      commaSep($.single_label),
    ),

    typeof_statement: $ => seq(
      "typeof",
      field('reserve', $.hexi),
    ),
    instanceof_statement: $ => seq(
      'instanceof',
      field('reserve', $.hexi),
      field('register', $.identifier),
    ),  

    returnundefined_statement: $ => 'returnundefined',

    return_statement: $ => 'return',

    add_statement: $ => seq(
      'add2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    dec_statement: $ => seq(
      'dec',
      field('reserve', $.hexi),
    ),

    sub_statement: $ => seq(
      'sub2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    mul_statement: $ => seq(
      'mul2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    div_statement: $ => seq(
      'div2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    mod_statement: $ => seq(
      'mod2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    eq_statement: $ => seq(
      'eq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    noteq_statement: $ => seq(
      'noteq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    less_statement: $ => seq(
      'less',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    lesseq_statement: $ => seq(
      'lesseq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    greater_statement: $ => seq(
      'greater',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    greatereq_statement: $ => seq(
      'greatereq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    and_statement: $ => seq(
      'and2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    or_statement: $ => seq(
      'or2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    xor_statement: $ => seq(
      'xor2',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),


    tonumeric_statement: $ => seq(
      'tonumeric',
      field('reserve', $.hexi),
    ),

    tryldglobalbyname_statement: $ => seq(
      'tryldglobalbyname',
      field('reserve', $.hexi),
      ',',
      '"',
      field('object', $.identifier,),
      '"'
    ),

    inc_statement: $ => seq(
      'inc',
      field('reserve', $.hexi),
    ),
    strictnoteq_statement: $ => seq(
      'strictnoteq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    stricteq_statement: $ => seq(
      'stricteq',
      field('reserve', $.hexi),
      ',',
      field('register', $.identifier),
    ),

    copyrestargs_statement: $ => seq(
      'copyrestargs',
      field('formal_param_pos', $.hexi),
    ),

    supercallspread_statement: $ => seq(
      'supercallspread',
      field('reserve', $.hexi),
      ',',
      field('arguments', $.identifier),
    ),

    throwcallwrong_statement: $ => seq(
      'throw.ifsupernotcorrectcall',
      field('register', $.hexi),
    ),

    throwifnotobject_statement: $ => seq(
      'throw.ifnotobject',
      field('register', $.identifier),
    ),

    asyncfunctionenter_statement: $ => 'asyncfunctionenter',

    neg_statement: $ => seq(
      'neg',
      field('reserve', $.hexi),
    ),

    asyncfunctionawaituncaught_statement: $ => seq(
      'asyncfunctionawaituncaught',
      field('function_object', $.identifier),
    ),

    suspendgenerator_statement: $ => seq(
      'suspendgenerator',
      field('generator', $.identifier),
    ),

    resumegenerator_statement: $ => 'resumegenerator',

    getresumemode_statement: $ => 'getresumemode',

    asyncfunctionresolve_statement: $ => seq(
      'asyncfunctionresolve',
      field('object', $.identifier),
    ),

    asyncfunctionreject_statement: $ => seq(
      'asyncfunctionreject',
      field('object', $.identifier),
    ),

    createemptyarray_statement: $ => seq(
      'createemptyarray',
      field('reserve', $.hexi),
    ),

    createobjectwithbuffer_statement: $ => seq(
      'createobjectwithbuffer',
      field('reserve', $.hexi),
      ',',
      $.literal,
    ),

    createemptyobject_statement: $ => 'createemptyobject',

    dynamic_import:$ => 'dynamicimport',

    isin_statement: $ => seq(
      'isin',
      field('reserve', $.hexi),
      ',',
      field('object', $.identifier),
    ),

    getmodulenamespace_statement: $ => seq(
      'getmodulenamespace',
      field('slot', $.hexi),
    ),

    // class_body:$ =>seq(
    //   '{',
    //   field('literal_num',$.deci),
    //   '[',
    //   repeat($.element),
    //   ']',
    //   '}'
    // ),
    method_in_class: $ => seq(
      'string:'

    ),
    checkholebyname_statement: $ => seq(
      "throw.undefinedifholewithname",
      '"',
      field('name', $.identifier),
      '"'
    ),

    elements: $ => commaSep1($.element),

    element: $ => seq(
      field(
        'type',
        choice($.type, 'method', 'method_affiliate')
      ),
      ':',
      choice(
        $.deci,
        $.hexi,
        $.float,
        $.identifier,
        $.string,
        $.temp_name,
      ),
      ','
    ),

    literal: $ => seq(
      '{',
      field('length', $.deci),
      '[',
      repeat($.element),
      ']',
      '}'
    ),

    comment: $ => choice(
      $.line_comment,
      $.block_comment,
    ),

    string: $ => choice(
      seq(
        '"',
        repeat(choice(
          alias($.unescaped_double_string_fragment, $.string_fragment),
          $.escape_sequence,
        )),
        '"',
      ),
      seq(
        '\'',
        repeat(choice(
          alias($.unescaped_single_string_fragment, $.string_fragment),
          $.escape_sequence,
        )),
        '\'',
      ),
    ),

    unescaped_double_string_fragment: _ => token.immediate(prec(1, /[^"\\\r\n]+/)),

    unescaped_single_string_fragment: _ => token.immediate(prec(1, /[^'\\\r\n]+/)),

    escape_sequence: _ => token.immediate(seq(
      '\\',
      choice(
        /[^xu0-7]/,
        /[0-7]{1,3}/,
        /x[0-9a-fA-F]{2}/,
        /u[0-9a-fA-F]{4}/,
        /u\{[0-9a-fA-F]+\}/,
        /[\r?][\n\u2028\u2029]/,
      ),
    )),

    comment: $ => choice(
      token(choice(
        seq('//', /.*/),
        seq(
          '/*',
          /[^*]*\*+([^/*][^*]*\*+)*/,
          '/',
        ),
      )),
    ),

    line_comment: _ => token(prec(PREC.COMMENT, seq('//', /.*/))),

    block_comment: _ => token(prec(PREC.COMMENT,
      seq('/*', /[^*]*\*+([^/*][^*]*\*+)*/, '/')
    )),

    identifier: $ => /[_a-zA-Z][_a-zA-Z0-9\-]*/,
    end_number: $ => /[\d\n]+(?:\.[\d\n]+){2}(?:\-[\d\n]+)?/,
    hexi: $ => /0[xX][0-9a-fA-F]+/,
    hexi_color: $ => /#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{8})/,
    chinese: $ => /[\u4e00-\u9fa5]/,
    deci: $ => /[0-9]+/,
    float: $ => /\d*\.\w*/,
    scientific: $ => /[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?/,
    string_fragment: _ => token.immediate(prec(1, /[^"\\]+/)),
    string_literal: $ => seq(
      '"', repeat($.string_fragment), '"',
    ),
  }


});


/**
 * Creates a rule to match one or more of the rules separated by separator
 *
 * @param {RuleOrLiteral} rule
 *
 * @param {RuleOrLiteral} separator
 *
 * @return {SeqRule}
 *
 */
function sep1(rule, separator) {
  return seq(rule, repeat(seq(separator, rule)));
}

/**
 * Creates a rule to match one or more of the rules separated by a comma
 *
 * @param {RuleOrLiteral} rule
 *
 * @return {SeqRule}
 *
 */
function commaSep1(rule) {
  return sep1(rule, ',');
}

function periodSep1(rule) {
  return sep1(rule, '.');
}

/**
 * Creates a rule to optionally match one or more of the rules separated by a comma
 *
 * @param {RuleOrLiteral} rule
 *
 * @return {ChoiceRule}
 *
 */
function commaSep(rule) {
  return optional(commaSep1(rule));
}

function periodSep(rule) {
  return optional(periodSep1(rule));
}





