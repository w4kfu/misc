# use aplib with ruby

require 'fiddle/import'

def hexdump(buf, start = 0, finish = nil, width = 16)
	ascii = ''
	counter = 0
	print '%06x  ' % start
	buf.each_byte do |c|
		if counter >= start
			print '%02x ' % c
			ascii << (c.between?(32, 126) ? c : ?.)
		if ascii.length >= width
			puts ascii 
			ascii = ''
			print '%06x  ' % (counter + 1)
		end
	end
	throw :done if finish && finish <= counter
		counter += 1
	end rescue :done
	puts '   ' * (width - ascii.length) + ascii
end

module ApLib
  extend Fiddle::Importer
  dlload 'aplib.dll'
  extern 'unsigned int aP_depack_asm(void*, void *)'
  extern 'size_t aPsafe_get_orig_size(void*)'
  extern 'size_t aPsafe_depack(void*, size_t, void*, size_t)'
end

buf_in = File.open('test_apilib.txt', 'rb') {|file| file.read }
# if the APLIB header is present
size = ApLib.aPsafe_get_orig_size(buf_in)
print "[+] %08X\n" % size
buf_out = "\x00" * size
ApLib.aPsafe_depack(buf_in, buf_in.length, buf_out, buf_out.size)
hexdump(buf_out)
# else APLIB header not present
#buf_out = "\x00" * 0x00003160
#print ApLib.aP_depack_asm(buf_in, buf_out)