require 'pp'

module Metasm

    module Wutils

      Ia32_X86_64_Reg = [["rax", "al", "ax", "eax", "al", "ah"],
                 ["rcx", "cl", "cx", "ecx", "cl", "ah"],
                 ["rdx", "dl", "dx", "edx", "dl", "dh"],
                 ["rbx", "bl", "bx", "ebx", "bl", "bh"],
                 ["rsp", "spl", "sp", "esp"],
                 ["rbp", "bpl", "bp", "ebp"],
                 ["rsi", "sil", "si", "esi"],
                 ["rdi", "dil", "di", "edi"],
                 ["r8", "r8b", "r8w", "r8d"],
                 ["r9", "r9b", "r9w", "r9d"],
                 ["r10", "r10b", "r10w", "r10d"],
                 ["r11", "r11b", "r11w", "r11d"],
                 ["r12", "r12b", "r12w", "r12d"],
                 ["r13", "r13b", "r13w", "r13d"],
                 ["r14", "r14b", "r14w", "r14d"],
                 ["r15", "r15b", "r15w", "r15d"]]

        def is_modrm(arg)
            return (arg != nil and (arg.kind_of? Ia32::ModRM or arg.kind_of? X86_64::ModRM))
        end

        def is_reg(arg)
            return (arg != nil and (arg.kind_of? Ia32::Reg or arg.kind_of? X86_64::Reg))
        end

        def is_numeric(arg)
            return (arg != nil and (arg.kind_of? Integer) or (arg.kind_of? Expression and arg.reduce_rec.kind_of? Integer))
        end

        def reg_alias(reg)
            reg = reg.to_s if (reg.kind_of? Ia32::Reg or reg.kind_of? X86_64::Reg)
            reg_alias = Ia32_X86_64_Reg.select{|regexpr| regexpr.include? reg}
            return [] if not reg_alias or reg_alias.length != 1
            return reg_alias.pop.collect{|reg_str| reg_str.to_sym}
        end

        def is_alias(reg1, reg2)
            return (reg_alias(reg1.to_s).include? reg2.to_s.to_sym)
        end

        def print_bt_log(bt_log)
            bt_log.each{|entry|
                case type = entry.first
                when :start
                    entry, expr, addr = entry
                    puts "[start] backtacking expr #{expr} from 0x#{addr.to_s(16)}"
                when :di
                    entry, to, from, instr = entry
                    puts "[update] instr #{instr},\n -> update expr from #{from} to #{to}\n"
                when :found
                    entry, final = entry
                    puts "[found] possible value: #{final.first}\n"
                when :up
                    entry, to, from, addr_down, addr_up = entry
                    puts "[up] addr 0x#{addr_down.to_s(16)} -> 0x#{addr_up.to_s(16)}"
                end
            }
        end

        def is_reg_write_immune(subflow, reg)
            subflow.each{ |di|
                if is_reg_write_access(di, reg)
                    return false
                end
            }
            return true
        end

        def is_reg_read_immune(subflow, reg)
            subflow.each{ |di|
                if is_reg_read_access(di, reg)
                    return false
                end
            }
            return true
        end

        def is_reg_rw_access(di, reg)
            return is_reg_write_access(di, reg) | is_reg_read_access(di, reg)
        end

        def is_reg_rw_access_immune(subflow, reg)
            subflow.each{ |di|
                if is_reg_rw_access(di, reg)
                    return false
                end
            }
            return true
        end

        def is_reg_write_access(di, reg)
            begin
                b = di.backtrace_binding ||= di.instruction.cpu.get_backtrace_binding(di)
            rescue Exception => e
                puts e.message
                puts e.backtrace.inspect
                exit(0)
            end
            reg_sym = reg_alias(reg)
            return false if not reg_sym or reg_sym.length == 0
            write_reg = false
            b.keys.each{ |effect| write_reg = true if reg_alias(effect.to_s) == reg_sym}
            return write_reg
        end

        def is_reg_read_access(di, reg)
            begin
                b = di.backtrace_binding ||= di.instruction.cpu.get_backtrace_binding(di)
            rescue Exception => e
                puts e.message
                puts e.backtrace.inspect
                exit(0)
            end
            if ['call', 'jmp'].include? di.instruction.opname
                return true if (is_reg(di.instruction.args.first) and is_alias(di.instruction.args.first, reg))
            end
            reg_sym = reg_alias(reg)
            return false if not reg_sym or reg_sym.length == 0
            rd = (b.keys.grep(Indirection) + b.keys.grep(Expression)).map { |e| Expression[e].expr_indirections.map{|ind| ind.target} }.flatten
            rd += b.values
            return !(rd.map{|effect| Expression[effect].externals}.flatten & reg_sym).empty?
        end

        def print_block(dasm, block)
            puts block.list.map{ |instr|
                    opcodes = dasm.read_raw_data(instr.address, instr.bin_length).unpack('C*').map{|c| '%02X' % c}.join(' ')
                    ("0x#{instr.address.to_s(16)}" + "\t" + "%-40s" + "\t" + instr.instruction.to_s) % opcodes
                }.join("\n")
        end

        def print_block_info(dasm, block)
            puts "----------- BLOCK INFO -----------"
            puts "[+] block.address         : 0x#{block.address.to_s(16)}"
            puts "[+] block.list.length     : 0x#{block.list.length.to_s(16)}"
            puts "[+] block.from_normal     : #{block.from_normal.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.from_normal
            puts "[+] block.to_normal       : #{block.to_normal.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.to_normal
            puts "[+] block.from_subfuncret : #{block.from_subfuncret.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.from_subfuncret
            puts "[+] block.to_subfuncret   : #{block.to_subfuncret.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.to_subfuncret
            puts "[+] block.from_indirect   : #{block.from_indirect.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.from_indirect
            puts "[+] block.to_indirect     : #{block.to_indirect.map{ |i| if i.kind_of? Integer then (i.to_s(16)) else i end}.join(",")}" if block.to_indirect
            print_block(dasm, block)
            puts "----------------------------------"
        end

        def launch_gui(dasm, addr)
            Gui::DasmWindow.new("metasm disassembler", dasm, addr)
            dasm.gui.focus_addr(dasm.gui.curaddr, :graph)
            Gui.main
        end

        def get_prev_di(dasm, di)
            if di.block.list.first != di
                di.block.list[di.block.list.index(di) - 1]
            elsif di.block.from_normal.to_a.length == 1
                dasm.di_at(di.block.from_normal.first)
            end
        end

        def get_next_di(dasm, di)
            if di.block.list.last != di
                di.block.list[di.block.list.index(di) + 1]
            elsif di.block.to_normal.to_a.length == 1
                dasm.di_at(di.block.to_normal.first)
            end
        end

        def nop_di(di)
            return if not di
            di.comment = nil
            di.backtrace_binding = {}
            di.instruction.opname = 'nop'
            di.instruction.args = []
            di.opcode.args = []
            di.opcode.props = {}
            di.opcode.fields = {}
            di.opcode.bin = [0x90]
            di.opcode.bin_mask = [255]
        end

        def assemble(sc, cpu)
            sc = sc.split(';').map{|t|
                t.strip!
                if t.count("'")%2==1
                    quote=quote ? false : true
                end
                t+(quote ? ';' : "\n")}.join
            return Metasm::Shellcode.assemble(cpu, sc).encode_string
        end

        def sc_2_dasm(sc, cpu=Metasm::Ia32.new, callback_newaddr=nil)
            bin = assemble(sc, cpu)
            dasm = Shellcode.decode(bin, cpu).disassembler
            dasm.callback_newaddr = lambda { |orig, exprs| callback_newaddr.call(dasm, orig, exprs) } if callback_newaddr
            dasm.disassemble(0x00)
            return dasm
        end

        def info_instr(sc, cpu=Metasm::Ia32.new, callback_newaddr=nil)
            dasm = sc_2_dasm(sc, cpu, callback_newaddr)
            di = dasm.di_at(0x00)
            pp(di)
        end

    end
end