require 'test/unit'
require 'metasm'

require_relative '../wutils'

include Metasm
include Metasm::Wutils

class TestWutils < Test::Unit::TestCase

    @@cpu64 = Metasm::X64.new
    @@cpu32 = Metasm::Ia32.new
    @@cpu16 = Metasm::Ia32.new(16)

    def assemble(sc, cpu=@@cpu32)
        sc = sc.split(';').map{|t|
            t.strip!
            if t.count("'")%2==1
                quote=quote ? false : true
            end
            t+(quote ? ';' : "\n")}.join
        return Metasm::Shellcode.assemble(cpu, sc).encode_string
    end
    
    def sc_2_dasm(sc, cpu=@@cpu32)
        bin = assemble(sc, cpu)
        dasm = Shellcode.decode(bin, cpu).disassembler
        dasm.disassemble(0x00)
        return dasm
    end

    def test_is_modrm()
        di = sc_2_dasm("mov [eax], 42").di_at(0x00)
        assert_equal(is_modrm(di.instruction.args.first), true)
        assert_equal(is_modrm(di.instruction.args.last), false)
        di = sc_2_dasm("mov [rax], 42", @@cpu64).di_at(0x00)
        assert_equal(is_modrm(di.instruction.args.first), true)
        assert_equal(is_modrm(di.instruction.args.last), false)
        di = sc_2_dasm("xchg eax, ebp").di_at(0x00)
        assert_equal(is_modrm(di.instruction.args.first), false)
        assert_equal(is_modrm(di.instruction.args.last), false)
        di = sc_2_dasm("push rbp", @@cpu64).di_at(0x00)
        assert_equal(is_modrm(di.instruction.args.first), false)
        assert_equal(is_modrm(nil), false)
    end
    
    def test_is_reg()
        di = sc_2_dasm("mov eax, 42").di_at(0x00)
        assert_equal(is_reg(di.instruction.args.first), true)
        assert_equal(is_reg(di.instruction.args.last), false)
        di = sc_2_dasm("mov rax, 42", @@cpu64).di_at(0x00)
        assert_equal(is_reg(di.instruction.args.first), true)
        assert_equal(is_reg(di.instruction.args.last), false)
        di = sc_2_dasm("xchg eax, ebp").di_at(0x00)
        assert_equal(is_reg(di.instruction.args.first), true)
        assert_equal(is_reg(di.instruction.args.last), true)
        di = sc_2_dasm("push [rbp]", @@cpu64).di_at(0x00)
        assert_equal(is_reg(di.instruction.args.first), false)
        assert_equal(is_reg(nil), false)
    end
    
    def test_is_numeric()
        di = sc_2_dasm("mov [42], eax").di_at(0x00)
        assert_equal(is_numeric(di.instruction.args.first), false)
        assert_equal(is_numeric(di.instruction.args.last), false)
        di = sc_2_dasm("mov [rax], 42", @@cpu64).di_at(0x00)
        assert_equal(is_numeric(di.instruction.args.first), false)
        assert_equal(is_numeric(di.instruction.args.last), true)
        di = sc_2_dasm("xchg eax, ebp").di_at(0x00)
        assert_equal(is_numeric(di.instruction.args.first), false)
        assert_equal(is_numeric(di.instruction.args.last), false)
        di = sc_2_dasm("push rbp", @@cpu64).di_at(0x00)
        assert_equal(is_numeric(di.instruction.args.first), false)
        assert_equal(is_numeric(nil), false)
    end
    
    def test_is_reg_write_access()
        di = sc_2_dasm("mov eax, 42").di_at(0x00)
        assert_equal(is_reg_write_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_write_access(di, "esp"), false)
        di = sc_2_dasm("mov [42], eax", @@cpu64).di_at(0x00)
        assert_equal(is_reg_write_access(di, "eax"), false)
        di = sc_2_dasm("mov eax, ebx").di_at(0x00)
        assert_equal(is_reg_write_access(di, "eax"), true)
        assert_equal(is_reg_write_access(di, "ebx"), false)
        assert_equal(is_reg_write_access(di, "esp"), false)
        di = sc_2_dasm("mov [rax], 42", @@cpu64).di_at(0x00)
        assert_equal(is_reg_write_access(di, "rax"), false)
        di = sc_2_dasm("pop esp").di_at(0x00)
        assert_equal(is_reg_write_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_write_access(di, "esp"), true)
        di = sc_2_dasm("mov dword ptr [esp], esp").di_at(0x00)
        assert_equal(is_reg_write_access(di, di.instruction.args.first), false)
        assert_equal(is_reg_write_access(di, "edi"), false)
        di = sc_2_dasm("xchg eax, ebx").di_at(0x00)
        assert_equal(is_reg_write_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_write_access(di, di.instruction.args.last), true)
        assert_equal(is_reg_write_access(di, "ax"), true)
        di = sc_2_dasm("bswap ax").di_at(0x00)
        assert_equal(is_reg_write_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_write_access(di, "eax"), true)
    end
    
    def test_reg_alias()
        assert_equal(reg_alias("esp"), [:rsp, :spl, :sp, :esp])
        assert_equal(reg_alias("sp"), [:rsp, :spl, :sp, :esp])
        assert_equal(reg_alias("rsp"), [:rsp, :spl, :sp, :esp])
        assert_equal(reg_alias("spl"), [:rsp, :spl, :sp, :esp])
    end
    
    def test_is_reg_write_immune()
        sc = "mov ecx, [ecx+14h] ; mov eax, [ecx] ; mov edx, [eax+4] ; nop ; neg eax ; sbb eax, eax ; inc eax ; ret"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_write_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_write_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_write_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_write_immune(di.block.list, "edi"), true)
        sc = "pop edi ; xor al, al ; pop esi ; pop ebp ; ret 4"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_write_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_write_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_write_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_write_immune(di.block.list, "edi"), false)
    end
    
    def test_is_reg_read_access()
        di = sc_2_dasm("mov eax, 42").di_at(0x00)
        assert_equal(is_reg_read_access(di, di.instruction.args.first), false)
        assert_equal(is_reg_read_access(di, "esp"), false)
        di = sc_2_dasm("mov [42], eax", @@cpu64).di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), true)
        di = sc_2_dasm("mov eax, ebx").di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), false)
        assert_equal(is_reg_read_access(di, "ebx"), true)
        assert_equal(is_reg_read_access(di, "esp"), false)
        di = sc_2_dasm("mov [rax], 42", @@cpu64).di_at(0x00)
        assert_equal(is_reg_read_access(di, "rax"), true)
        di = sc_2_dasm("pop esp").di_at(0x00)
        assert_equal(is_reg_read_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_read_access(di, "esp"), true)
        di = sc_2_dasm("mov dword ptr [esp], esp").di_at(0x00)
        assert_equal(is_reg_read_access(di, di.instruction.args.first), false)
        assert_equal(is_reg_read_access(di, "esp"), true)
        assert_equal(is_reg_read_access(di, "edi"), false)
        di = sc_2_dasm("xchg eax, ebx").di_at(0x00)
        assert_equal(is_reg_read_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_read_access(di, di.instruction.args.last), true)
        assert_equal(is_reg_read_access(di, "ax"), true)
        di = sc_2_dasm("bswap ax").di_at(0x00)
        assert_equal(is_reg_read_access(di, di.instruction.args.first), true)
        assert_equal(is_reg_read_access(di, "eax"), true)
        di = sc_2_dasm("mov rax, [rdi]", @@cpu64).di_at(0x00)
        assert_equal(is_reg_read_access(di, "rdi"), true)
        di = sc_2_dasm("push eax").di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), true)
        di = sc_2_dasm("call eax").di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), true)
        di = sc_2_dasm("jmp eax").di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), true)
        di = sc_2_dasm("jmp [eax]").di_at(0x00)
        assert_equal(is_reg_read_access(di, "eax"), true)
    end
    
    def test_is_reg_read_immune()
        sc = "mov ecx, [ecx+14h] ; mov eax, [ecx] ; mov edx, [eax+4] ; nop ; neg eax ; sbb eax, eax ; inc eax ; ret"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_read_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_read_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_read_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_read_immune(di.block.list, "edi"), true)
        sc = "pop edi ; xor al, al ; pop esi ; pop ebp ; ret 4"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_read_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_read_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_read_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_read_immune(di.block.list, "edi"), true)
        sc = "mov ecx, [ecx+42h] ; mov eax, [ecx] ; call eax"
        assert_equal(is_reg_read_immune(di.block.list, "eax"), false)
    end
    
    def test_is_reg_rw_access_immune()
        sc = "mov ecx, [ecx+14h] ; mov eax, [ecx] ; mov edx, [eax+4] ; nop ; neg eax ; sbb eax, eax ; inc eax ; ret"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_rw_access_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_rw_access_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_rw_access_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_rw_access_immune(di.block.list, "edi"), true)
        sc = "pop edi ; xor al, al ; pop esi ; pop ebp ; ret 4"
        di = sc_2_dasm(sc).di_at(0x00)
        assert_equal(is_reg_rw_access_immune(di.block.list, "esp"), false)
        assert_equal(is_reg_rw_access_immune(di.block.list, "eax"), false)
        assert_equal(is_reg_rw_access_immune(di.block.list, "ebx"), true)
        assert_equal(is_reg_rw_access_immune(di.block.list, "edi"), false)
    end
    
end