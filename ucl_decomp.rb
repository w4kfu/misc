#!/usr/bin/ruby

# decompress UCL data : http://www.oberhumer.com/opensource/ucl/

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

def getbit_8(bb, buf, ilen)
	if ((bb & 0x7F) != 0)
		bb = (bb * 2)
	else
		bb = (buf[ilen].ord * 2 + 1)
		ilen = ilen + 1
	end
	return bb, ilen, (bb >> 8) & 1
end

def ucl_decomp(buf)
	buf_out = ""
	bb = 0
	ilen = 0
	last_m_off = 1
	while true do
		loop do
			bb, ilen, res = getbit_8(bb, buf, ilen)
			break if (res == 0)
			buf_out += buf[ilen]
			ilen = ilen + 1
		end
		m_off = 1
		loop do
			bb, ilen, res = getbit_8(bb, buf, ilen)
			m_off = m_off * 2 + res
			bb, ilen, res = getbit_8(bb, buf, ilen)
			break if (res != 0)
		end
		if m_off == 2
			m_off = last_m_off
		else
			m_off = (m_off - 3) * 256 + buf[ilen].ord
			ilen = ilen + 1
			if (m_off == 0xffffffff)
				return buf_out
			end
			m_off = m_off + 1
			last_m_off = m_off
		end
		bb, ilen, m_len = getbit_8(bb, buf, ilen)
		bb, ilen, res = getbit_8(bb, buf, ilen)
		m_len = m_len * 2 + res
		if m_len == 0
			m_len = m_len + 1
			loop do
				bb, ilen, res = getbit_8(bb, buf, ilen)
				m_len = m_len * 2 + res
				bb, ilen, res = getbit_8(bb, buf, ilen)
				break if (res != 0)
			end
			m_len = m_len + 2
		end
		if (m_off > 0xd00)
			m_len = m_len + 1
		end
		for i in (0..m_len)
			buf_out += buf_out[buf_out.length - m_off]
		end
		m_len = 0
	end
end


buf_in = File.open('test_decomp.bin', 'rb') {|file| file.read }

size_in = buf_in[4,8].unpack("L").shift

buf_in = buf_in[8, buf_in.length]

buf_out = ucl_decomp(buf_in)

hexdump(buf_out)