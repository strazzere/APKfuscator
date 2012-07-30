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
# Utility class for APKfuscator
#
module Utilities

  class ArgumentError < RuntimeError; end

  #
  # Verbosity helpers
  #
  def self.head_info(information=nil)
    puts '[+] ' + information
  end

  def self.info(information=nil)
    puts ' [+] ' + information
  end

  def self.warn(warning=nil)
    puts ' [!] ' + warning
  end

  def self.divisible_4(data=nil)
    if(data.length % 4 != 0)
      ((data.length % 4)..3).each do
        data += Utilities.hex_to_char_string "00"
      end
    end

    return data
  end

  def self.swap_4(int=nil)
    hex = sprintf("%08X", int)
    hex = sprintf("%c%c%c%c", hex[6..7].to_i(16), hex[4..5].to_i(16), hex[2..3].to_i(16), hex[0..1].to_i(16))
    return hex
  end

  def self.swap_2(int=nil)
    hex = sprintf("%04X", int)
    hex = sprintf("%c%c", hex[2..3].to_i(16), hex[0..1].to_i(16))
    return hex
  end

  def self.hex_to_char_string(string=nil)
    new_string = ''
    (0..string.length-1).step(2).each do |i|
      new_string = new_string + sprintf("%c", string[i..i+1].to_i(16))
    end

    return new_string
  end

  class EncodedValue
    ANNOTATION_VALUE_TYPE_MASK = "1f".to_i(16)     # low 5 bits
    ANNOTATION_VALUE_ARG_SHIFT = "05".to_i(16)

    ANNOTATION_BYTE            = "00".to_i(16)
    ANNOTATION_SHORT           = "02".to_i(16)
    ANNOTATION_CHAR            = "03".to_i(16)
    ANNOTATION_INT             = "04".to_i(16)
    ANNOTATION_LONG            = "06".to_i(16)
    ANNOTATION_FLOAT           = "10".to_i(16)
    ANNOTATION_DOUBLE          = "11".to_i(16)
    ANNOTATION_STRING          = "17".to_i(16)
    ANNOTATION_TYPE            = "18".to_i(16)
    ANNOTATION_FIELD           = "19".to_i(16)
    ANNOTATION_METHOD          = "1A".to_i(16)
    ANNOTATION_ENUM            = "1B".to_i(16)
    ANNOTATION_ARRAY           = "1C".to_i(16)
    ANNOTATION_ANNOTATION      = "1D".to_i(16)
    ANNOTATION_NULL            = "1E".to_i(16)
    ANNOTATION_BOOLEAN         = "1F".to_i(16)

    def self.resolve_type(type=nil)
      if(!type.nil?)
        case(type)
        when "00".to_i(16)
          return "BYTE"
        when "02".to_i(16)
          return "SHORT"
        when "03".to_i(16)
          return "CHAR"
        when "04".to_i(16)
          return "INT"
        when "06".to_i(16)
          return "LONG"
        when "10".to_i(16)
          return "FLOAT"
        when "11".to_i(16)
          return "DOUBLE"
        when "17".to_i(16)
          return "STRING"
        when "18".to_i(16)
          return "TYPE"
        when "19".to_i(16)
          return "FIELD"
        when "1A".to_i(16)
          return "METHOD"
        when "1B".to_i(16)
          return "ENUM"
        when "1C".to_i(16)
          return "ARRAY"
        when "1D".to_i(16)
          return "ANNOATION"
        when "1E".to_i(16)
          return "NULL"
        when "1F".to_i(16)
          return "BOOLEAN"
        end
      end
      raise ArgumentError.new 'The type passed [ ' + type.to_s + ' ] cannot be resolved to a type of encoded value!'
    end

    def self.write_encoded_value(value_type, value_arg, data)
      # TODO: there should be some error checking on variables instead of just blind writing in here

      # Create header byte - must have leading 0!
      buffer = sprintf("%02x", (value_type + (value_arg << ANNOTATION_VALUE_ARG_SHIFT)))

      # since thi function pre-cooks the characters on return, we need to not re-encode them if we recurse through
      converted_chars = ''

      # Somethings need to be handled differently, specifically arrays
      case(value_type)
      when ANNOTATION_ARRAY
        # Write out the size of the array
        buffer += sprintf("%02X", data[:size])
        # Recursively print other values
        data[:data].each do |data|
          converted_chars += Utilities::EncodedValue.write_encoded_value(data[:value_type], data[:value_arg], data[:data])
        end
      else
        # Add the data, having nil for data is acceptable, we just don't write anything out
        if(!data.nil?)
          # Ensure we have a leading 0 if necessary
          buffer += sprintf("%02X", data)
        end
      end

      return Utilities.hex_to_char_string(buffer) + converted_chars
    end

    def self.read_encoded_value(value=nil)
      header_byte = value[0..1].to_i(16)
      value_type = header_byte & ANNOTATION_VALUE_TYPE_MASK
      value_arg = header_byte >> ANNOTATION_VALUE_ARG_SHIFT
      offset_adjustment = 1

      case(value_type)
      when ANNOTATION_BYTE
        if(value_arg != 0)
          warn 'Bogus value for type BYTE'
        end
        data = value[1..2]
        offset_adjustment += 1
      when ANNOTATION_SHORT, ANNOTATION_CHAR
        if(value_arg > 1)
          warn 'Bogus value for type CHAR/SHORT'
        end
        # TODO : no fscking clue
        data = value[value_arg+1..value_arg+2].to_i(16)
        offset_adjustment += 1
      when ANNOTATION_INT, ANNOTATION_FLOAT
        if(value_arg > 3)
          warn 'Bogus value for type INT/FLOAT'
        end
        val = value[2..3 + (value_arg * 2)].to_i(16)
        data = ((val & 0xFF000000) >> 24) << 0
        if(value_arg >= 1)
          data += ((val & 0x00FF0000) >> 16) << 8
          if(value_arg >= 2)
            data += ((val & 0x0000FF00) >> 8) << 16
            if(value_arg == 3)
              data += ((val & 0x000000FF) >> 0) << 24
            end
          end
        end
        offset_adjustment += value_arg + 1
      when ANNOTATION_LONG, ANNOTATION_DOUBLE
        data = value[value_arg+1..value_arg+2].to_i(16)
        offset_adjustment += 1
      when ANNOTATION_STRING
        if(value_arg > 3)
          warn 'Bogus value for type STRING'
        end
        # TODO : does this need to be uleb?
        data = value[2..3].to_i(16)
        #readunsignedlittleendian -- index to a string
        offset_adjustment += 1
      when ANNOTATION_TYPE
        if(value_arg > 3)
          warn 'Bogus value for type TYPE'
        end
        data = value[2..3].to_i(16)
        offset_adjustment += 1
        # Same as string above, just for a type index
      when ANNOTATION_FIELD, ANNOTATION_ENUM
        if(value_arg > 3)
          warn 'Bogus value for type FIELD/ENUM'
        end
        data = value[2..3].to_i(16)
        offset_adjustment += 1
        # Same as above, just field index
      when ANNOTATION_METHOD
        if(value_arg > 3)
          warn 'Bogus value for type METHOD'
        end
        data = value[2..3].to_i(16)
        offset_adjustment += 1
        # Same as above, just method index
      when ANNOTATION_ARRAY
        if(value_arg != 0)
          warn 'Bogus value for type ARRAY'
        end
        # Read the size of the array
        size, total_offset = Utilities::LEB128.read_unsigned_leb128(value[2..value.length])

        # Recursively get the data for the array
        array = []
        (0..size-1).each do |index|
          value_t, value_a, data_item, array_offset = Utilities::EncodedValue.read_encoded_value(value[(3+total_offset)..value.length])
          array << {
            :value_type => value_t,
            :value_arg => value_a,
            :data => data_item
          }
          # offset * 2 since we each char is a bit now and want to skip a byte
          total_offset += (array_offset * 2)
        end

        offset_adjustment += total_offset
        data = {
          :size => size,
          :data => array
        }
      when ANNOTATION_ANNOTATION # how meta...
        if(value_arg != 0)
          warn 'Bogus value for type ANNOTATION'
        end
        raise RuntimeError.new'Not yet implemented!'
        # TODO : NEEDS TO BE DONE
        # get index from unsignedleb128 - this is a type_id index
        # get size from unsignedleb128
        # get the index inside this - this is a string_id index
        # resurse through this function again
      when ANNOTATION_NULL
        if(value_arg != 0)
          warn 'Bogus value for type NULL'
        end
        data = nil
      when ANNOTATION_BOOLEAN
        if(value_arg > 1)
          warn 'Bogus value for type BOOLEAN'
        end
      else
        raise RuntimeError.new 'Something bad probably happened...'
      end

      return value_type, value_arg, data, offset_adjustment
    end
  end

  class LEB128
    # Function will convert an unsigned lower endian base 128
    # which is represented in a hex string.
    #
    # Retuns a integer value fot he unsigned leb128
    def self.read_unsigned_leb128(value=nil)
      const_val = "7f".to_i(16)

      result = value[0..1].to_i(16)
      extra_offset = 1
      if(result > const_val)
        extra_offset += 1
        result = (result & const_val) | ((value[2..3].to_i(16)  & const_val) << 7)
        if(value[2..3].to_i(16) > const_val)
          extra_offset += 1
          result |= ((value[4..5].to_i(16) & const_val) << 14)
          if(value[4..5].to_i(16) > const_val)
            extra_offset += 1
            result |= ((value[6..7].to_i(16) & const_val) << 21)
            if(value[6..8].to_i(16) > const_val)
              extra_offset += 1
              result |= ((value[8..9].to_i(16) & const_val) << 28)
            end
          end
        end
      end

      return result, extra_offset
    end

    # Function will convert an integer value in to a
    # unsigned lower endian base 128 hex based string.
    #
    # Returns a string represented conversion of the leb128 int
    def self.write_uleb128(value=nil)
      if(value.nil?)
        warn 'Attempting to write a "nil" value as a uleb128 - this probably isn\'t going to end well'
      end

      output = ''
      tmp = 0

      while true
        tmp = value & "7f".to_i(16)
        if(tmp != value)
          output += sprintf("%02X", tmp | "80".to_i(16))
          value >>= 7
        else
          output += sprintf("%02X", tmp)
          break
        end
      end

      return Utilities.hex_to_char_string(output)
    end
  end
end
