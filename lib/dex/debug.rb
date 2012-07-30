#    APKfuscator - A generic DEX file obfuscator and munger
#    Copyright (C) 2012 Tim Strazzere <strazz@gmail.com>, <tim.strazzere@mylookout.com>
#    Lookout Mobile Security http://www.mylookout.com/
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

#
# Debug information for use by APKfuscator
#
module Dex
  class Debug

    class ArgumentError < RuntimeError; end

    # Debug opcodes and constants
    DBG_END_SEQUENCE         = '00'.to_i(16),
    DBG_ADVANCE_PC           = '01'.to_i(16),
    DBG_ADVANCE_LINE         = '02'.to_i(16),
    DBG_START_LOCAL          = '03'.to_i(16),
    DBG_START_LOCAL_EXTENDED = '04'.to_i(16),
    DBG_END_LOCAL            = '05'.to_i(16),
    DBG_RESTART_LOCAL        = '06'.to_i(16),
    DBG_SET_PROLOGUE_END     = '07'.to_i(16),
    DBG_SET_EPILOGUE_BEGIN   = '08'.to_i(16),
    DBG_SET_FILE             = '09'.to_i(16),
    DBG_FIRST_SPECIAL        = '0a'.to_i(16),
    DBG_LINE_BASE            = -4,
    DBG_LINE_RANGE           = 15,

    def self.read_op_code(chunk=nil)
      if(chunk.nil?)
        raise ArgumentError.new 'Unable to parse a debug opcode from a nil chunk!'
      end

      # Get the first part which should be an opcode
      opcode = chunk[0..1].to_i(16)

      case(opcode)
      when DBG_END_SEQUENCE
      when DBG_ADVANCE_PC
      when DBG_ADVANCE_LINE
      when DBG_START_LOCAL

      when DBG_START_LOCAL_EXTENDED
      when DBG_END_LOCAL
      when DBG_RESTART_LOCAL
      when DBG_SET_PROLOGUE_END
      when DBG_SET_EPILOGUE_BEGIN
      when DBG_SET_FILE
      when DBG_FIRST_SPECIAL
      when DBG_LINE_BASE
      when DBG_LINE_RANGE
      else
        raise RuntimeError.new 'Got a weird debug opcode!'
      end
    end
  end
end
