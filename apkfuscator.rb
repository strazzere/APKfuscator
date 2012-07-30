# -*- coding: utf-8 -*-
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

require 'rubygems'
require 'zlib' # Required for checksum (adler32)
require 'digest/sha1' # Required for signature
require 'lib/utilities.rb'
require 'pp'

class DexFile

  DEX                        = 0
  ODEX                       = 1

  DEX_VER_35                 = 35
  DEX_VER_36                 = 36
  DEX_OPT_VER_36             = 36

  DEX_MAGIC                  = "dex\n"
  DEX_OPT_MAGIC              = "dey\n"
  DEX_DEP_MAGIC              = "deps"

  DEX_MAGIC_VERS_35          = "035\0" # API levels 13 and below
  DEX_MAGIC_VERS_36          = "036\0" # API levels 14 and above
  DEX_OPT_MAGIC_VERS         = "036\0"

  DEFAULT_HEADER_SIZE        = '70'.to_i(16)
  ENDIAN_TAG                 = '12345678'.to_i(16)

  # Map Item Types
  Header_Item                = "0000".to_i(16)
  String_Id_Item             = "0001".to_i(16)
  Type_Id_Item               = "0002".to_i(16)
  Proto_Id_Item              = "0003".to_i(16)
  Field_Id_Item              = "0004".to_i(16)
  Method_Id_Item             = "0005".to_i(16)
  Class_Def_Item             = "0006".to_i(16)
  Map_List                   = "1000".to_i(16)
  Type_List                  = "1001".to_i(16)
  Annotation_Set_Ref_List    = "1002".to_i(16)
  Annotation_Set_Item        = "1003".to_i(16)
  Class_Data_Item            = "2000".to_i(16)
  Code_Item                  = "2001".to_i(16)
  String_Data_Item           = "2002".to_i(16)
  Debug_Info_Item            = "2003".to_i(16)
  Annotation_Item            = "2004".to_i(16)
  Encoded_Array_Item         = "2005".to_i(16)
  Annotations_Directory_Item = "2006".to_i(16)

  # ACCESS_FLAGS for class def items
  ACC_PUBLIC                = "00001".to_i(16) # class, field, method, ic
  ACC_PRIVATE               = "00002".to_i(16) # field, method, ic
  ACC_PROTECTED             = "00004".to_i(16) # field, method, ic
  ACC_STATIC                = "00008".to_i(16) # field, method, ic
  ACC_FINAL                 = "00010".to_i(16) # class, field, method, ic
  ACC_SYNCHRONIZED          = "00020".to_i(16) # method (only allowed on natives)
  ACC_SUPER                 = "00020".to_i(16) # class (not used in Dalvik)
  ACC_VOLATILE              = "00040".to_i(16) # field
  ACC_BRIDGE                = "00040".to_i(16) # method (1.5)
  ACC_TRANSIENT             = "00080".to_i(16) # field
  ACC_VARARGS               = "00080".to_i(16) # method (1.5)
  ACC_NATIVE                = "00100".to_i(16) # method
  ACC_INTERFACE             = "00200".to_i(16) # class, ic
  ACC_ABSTRACT              = "00400".to_i(16) # class, method, ic
  ACC_STRICT                = "00800".to_i(16) # method
  ACC_SYNTHETIC             = "01000".to_i(16) # field, method, ic
  ACC_ANNOTATION            = "02000".to_i(16) # class, ic (1.5)
  ACC_ENUM                  = "04000".to_i(16) # class, field, ic (1.5)
  ACC_CONSTRUCTOR           = "10000".to_i(16) # method (Dalvik only)
  ACC_DECLARED_SYNCHRONIZED = "20000".to_i(16) # method (Dalvik only)
  ACC_CLASS_MASK            = (ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE |
                               ACC_ABSTRACT | ACC_SYNTHETIC | ACC_ANNOTATION |
                               ACC_ENUM)
  ACC_INNER_CLASS_MASK      = (ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED |
                               ACC_STATIC)
  ACC_FIELD_MASK            = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED |
                               ACC_STATIC | ACC_FINAL | ACC_VOLATILE |
                               ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM)
  ACC_METHOD_MASK           = (ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED |
                               ACC_STATIC | ACC_FINAL | ACC_SYNCHRONIZED |
                               ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE |
                               ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC |
                               ACC_CONSTRUCTOR | ACC_DECLARED_SYNCHRONIZED)

  class ArgumentError < RuntimeError; end

  def initialize(file=nil, verbose=false)
    @verbose = verbose

    if(file.nil?)
      raise RuntimeError.new 'Cannot open a nil file!'
    end

    if(@verbose)
      Utilities.head_info ' loaded file [ ' + file + ' ]'
    end

    @dex_file = File.new(file, 'r+')
    @dex_type = nil
    @dex_ver = nil
    @header = {
      :magic => nil,
      :magic_ver => nil,
      :checksum => nil,
      :signature => nil,
      :file_size => nil,
      :header_size => nil,
      :endian_tag => nil,
      # sections
      :link_size => nil,
      :link_offset => nil,
      # map size is listed as first unsigned int (4) at the beginning,
      # must reside inside the data section
      :map_offset => nil,
      :type_ids_size => nil,
      :type_ids_offset => nil,
      :proto_ids_size => nil,
      :proto_ids_offset => nil,
      :field_ids_size => nil,
      :field_ids_offset => nil,
      :method_ids_size => nil,
      :method_ids_offset => nil,
      :class_defs_size => nil,
      :class_defs_offset => nil,
      :data_size => nil,
      :data_offset => nil
    }

    @map = {}
    @sections = {}

    get_header_information
    get_map_information
    get_sections # must be called after map has been read since that gives us the totals
  end

  #
  # Nerf the size of the header -- must be divisible evenly by 4
  #
  def nerf_header_size(new_size=nil, file_to_inject=nil)
    if(new_size.nil?)
      new_size = 116
    end

    # Make sure it aligns properly with a u4
    if(new_size % 4 != 0)
      raise ArgumentError.new 'Unable to nerf the header size to something that is not divisible by 4!'
    end

    # If an injectable is passed, then lets save it to an object we can reference later
    @injecting_file = file_to_inject

    set_header('header_size', new_size)
  end

  #
  # Nerf a code section with either a new class or modify something
  #
  # {
  #   :code => code_to_inject,
  #   :code_length => length_of_injected_code, # The length of opcodes
  #   :method_index => method_index_to_inject_at
  # }
  def nerf_code_section(code_nerf=nil)
    if(code_nerf.nil?)
      raise ArgumentError.new 'Unable to use a nil code_nerf object'
    end

    if(@code_nerf.nil?)
      @code_nerf = []
    end

    @code_nerf << code_nerf
  end

  #
  # Nerf something inside of the string section, either modifying something existing or adding something new
  #
  # {
  #   :match => string_to_change,
  #   :value => value_to_change_string_to
  # }
  def nerf_string_section(string_nerf=nil)
    if(string_nerf.nil?)
      raise ArgumentError.new 'Unable to use a nil string_nerf object'
    end

    if(@string_nerf.nil?)
      @string_nerf = []
    end

    @string_nerf << string_nerf
  end

  def save_modified(file_name=nil)
    if(file_name.nil?)
      file_name = File.dirname(__FILE__) + 'modified'
    end

    if(@verbose)
      Utilities.head_info 'Writing file [ ' + file_name + ' ] for (hopefully) [ ' + File.size?(@dex_file).to_s + ' ] bytes'
    end

    file = File.new(file_name, 'w+')
    buffer = ''

    # After the header - we should be able to calculate the size of each section below until we hit the data section

    string_id_offset = get_header('header_size')
    type_id_offset = string_id_offset + @sections[:string_id_list].length * 4
    proto_id_offset = type_id_offset + @sections[:type_id_list].length * 4
    field_id_offset = proto_id_offset + @sections[:proto_id_list].length * 12
    method_id_offset = field_id_offset + @sections[:field_id_list].length * 8
    class_def_offset = method_id_offset + @sections[:method_id_list].length * 8
    map_offset = class_def_offset + @sections[:class_def_items].length * "20".to_i(16)
    pre_data_length = map_offset + create_map.length

    # The following sections could in theory have spaces between them, possibly be out of order also
    string_id_list, string_data = create_string_id_list(pre_data_length)
    if(string_id_list.length != get_header('string_ids_size') * 4)
      Utilities.warn 'String Id section does not appear to be the proper size, expected [ ' +  (get_header('string_ids_size') * 4).to_s
      + ' ] but was [ ' + string_id_list.length.to_s + ' ]'
    end
    # Set map object
    map_item = get_section_from_map String_Id_Item
    map_item[:size] = @sections[:string_id_list].length
    map_item[:offset] = string_id_offset
    # Set header offset
    set_header('string_ids_size', @sections[:string_id_list].length)
    set_header('string_ids_offset', string_id_offset)
    # Append the string_id_list to the pre-data section buffer
    buffer += string_id_list
    # Append the string data to the data section
    data = string_data

    # Doesn't actually interface with the data section
    # -- only resolves indexes directly from the strings table
    type_id_list = create_type_id_list
    if(type_id_list.length != get_header('type_ids_size') * 4)
      Utilities.warn 'Type Id section does not appear to be the proper size!'
    end
    # Set map object
    map_item = get_section_from_map Type_Id_Item
    map_item[:size] = @sections[:type_id_list].length
    map_item[:offset] = type_id_offset
    # Set header offset
    set_header('type_ids_size', @sections[:type_id_list].length)
    set_header('type_ids_offset', type_id_offset)
    # Append the type_id_list to the pre-data section buffer
    buffer += type_id_list

    proto_id_list, parameter_data = create_proto_id_list(pre_data_length + data.length)
    if(proto_id_list.length != get_header('proto_ids_size') * 12)
      Utilities.warn 'Proto Id section does not appear to be the proper size!'
    end
    # Set map object
    map_item = get_section_from_map Proto_Id_Item
    map_item[:size] = @sections[:proto_id_list].length
    map_item[:offset] = proto_id_offset
    # Set header offset
    set_header('proto_ids_size', @sections[:proto_id_list].length)
    set_header('proto_ids_offset', proto_id_offset)
    # Append the proto_id_list to the pre-data section buffer
    buffer += proto_id_list
    # Append the parameter data to the data section
    data += parameter_data

    # Doesn't actually interface with data section
    # -- resolves indexes of two types and a string
    field_id_list = create_field_id_list
    if(field_id_list.length != get_header('field_ids_size') * 8)
      Utilities.warn 'Field Id section does not appear to be the proper size!'
    end
    # Set map object
    map_item = get_section_from_map Field_Id_Item
    map_item[:size] = @sections[:field_id_list].length
    map_item[:offset] = field_id_offset
    # Set header offset
    set_header('field_ids_size', @sections[:field_id_list].length)
    set_header('field_ids_offset', field_id_offset)
    # Append the field_id_list to the pre-data section buffer
    buffer += field_id_list

    # Doesn't actually interface with data section
    # -- resolves an index for a type, a proto and a string
    method_id_list = create_method_id_list
    if(method_id_list.length != get_header('method_ids_size') * 8)
      Utilities.warn 'Method Id section does not appear to be the proper size!'
    end
    # Set map object
    map_item = get_section_from_map Method_Id_Item
    map_item[:size] = @sections[:method_id_list].length
    map_item[:offset] = method_id_offset
    # Set header offset
    set_header('method_ids_size', @sections[:method_id_list].length)
    set_header('method_ids_offset', method_id_offset)
    # Append the method_id_list to the pre-data section buffer
    buffer += method_id_list

    # Heavy interaction with the data section
    # class_def_data_block is going to end up containing;
    # -- interfaces
    # -- annotations [ annotation directories, annotation sets and annotation items ]
    # -- class_data_items
    # -- static_values
    # -- code_items
    # -- debug_items
    class_def_items, class_def_data_block = create_class_def_items(pre_data_length + data.length)
    if(class_def_items.length != get_header('class_defs_size') * "20".to_i(16))
      Utilities.warn 'Class definition section does not appear to be the proper size!'
    end
    # Set map object
    map_item = get_section_from_map Class_Def_Item
    map_item[:size] = @sections[:class_def_items].length
    map_item[:offset] = class_def_offset
    # Set header offset
    set_header('class_defs_size', @sections[:class_def_items].length)
    set_header('class_defs_offset', class_def_offset)
    # Append the class_def_items to the pre-data section buffer
    buffer += class_def_items
    # Append the data we've just generated
    data += class_def_data_block

    # Set map object
    map_item = get_section_from_map Map_List
    map_item[:size] = 1
    map_item[:offset] = map_offset
    # Fix the offset in the header for the map
    set_header('map_offset', map_offset)

    # Add a fresh map the to data section
    data = create_map + data

    # Add the data
    buffer += data

    # Set data offset and length
    set_header('data_size', data.length)
    set_header('data_offset', map_offset)

    set_header('file_size', get_header('header_size') + buffer.length)

    # Create and preprend the fixed header
    buffer = create_header + buffer

    signed_dex = sign_dex(buffer)

    file.write(signed_dex)
    file.close
    if(@verbose)
      Utilities.info 'Wrote [ ' + File.stat(file_name).size.to_s + ' ] bytes'
    end
  end

  def sign_dex(buffer=nil)
    # Check if it's nil or smaller than the minimum header size
    if(buffer.nil? || buffer.length < 0x70)
      raise ArgumentError.new 'Unable to sign a dex file which is nil!'
    end

    # Get sha1 of everything past where the sha1 lives
    signature = Digest::SHA1.hexdigest(buffer[32..buffer.length])

    # build the sha1 plus data beyond it
    sha_buf = Utilities.hex_to_char_string(signature)
    sha_buf += buffer[32..buffer.length]

    # get the adler32 of the sha'ed buffer
    checksum = Zlib.adler32(sha_buf, nil).to_i

    # copy over the magic bytes of the dex file
    signed = buffer[0..7]
    signed += Utilities.swap_4(checksum)
    signed += sha_buf

    return signed
  end

  def get_full_header
    return @header
  end

  def create_header
    header = ''
    header += @header[:magic].pack('H*')
    header += @header[:magic_ver].pack('H*')
    header += Utilities.swap_4(@header[:checksum])
    header += Utilities.hex_to_char_string(@header[:signature])
    header += Utilities.swap_4(@header[:file_size])
    header += Utilities.swap_4(@header[:header_size])
    header += Utilities.swap_4(@header[:endian])
    header += Utilities.swap_4(@header[:link_size])
    header += Utilities.swap_4(@header[:link_offset])
    header += Utilities.swap_4(@header[:map_offset])
    header += Utilities.swap_4(@header[:string_ids_size])
    header += Utilities.swap_4(@header[:string_ids_offset])
    header += Utilities.swap_4(@header[:type_ids_size])
    header += Utilities.swap_4(@header[:type_ids_offset])
    header += Utilities.swap_4(@header[:proto_ids_size])
    header += Utilities.swap_4(@header[:proto_ids_offset])
    header += Utilities.swap_4(@header[:field_ids_size])
    header += Utilities.swap_4(@header[:field_ids_offset])
    header += Utilities.swap_4(@header[:method_ids_size])
    header += Utilities.swap_4(@header[:method_ids_offset])
    header += Utilities.swap_4(@header[:class_defs_size])
    header += Utilities.swap_4(@header[:class_defs_offset])
    header += Utilities.swap_4(@header[:data_size])
    header += Utilities.swap_4(@header[:data_offset])

    if(@verbose && (get_header('header_size') - DEFAULT_HEADER_SIZE) != 0)
      Utilities.info 'Padding the end of the header with [ ' + (get_header('header_size') - DEFAULT_HEADER_SIZE).to_s + ' ] bytes, since size has been nerfed!'
    end


    if(!@injecting_file.nil?)
      # Inject the other dex file here if need be
      extra_file = File.new(@injecting_file, 'r+')
      dex_contents = extra_file.read(File.size?(extra_file))

      # Inject other dex file and xor it
      dex_contents.each_byte do |byte|
        # header += Utilities.hex_to_char_string((byte).to_s(16))
        header += Utilities.hex_to_char_string((byte ^ 0xd1).to_s(16))
      end
    else
      (1..(get_header('header_size') - DEFAULT_HEADER_SIZE)).each do
        header += Utilities.hex_to_char_string "00"
      end
    end

    return header
  end

  # Contains offsets to the struct;
  # {
  #   :string_size,
  #   :string_contents
  # }
  def create_string_id_list(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create a string_id_list or string_table without an offset!'
    end
    string_id_list = ''
    string_section = ''

    fix_map_item(String_Data_Item, @sections[:string_id_list].length, expected_data_offset)

    @sections[:string_id_list].each do |index, string_id|
      # Process any string_nerf objects we have
      if(!@string_nerf.nil?)
        @string_nerf.each do |string_nerf|
          if(string_nerf[:match] == string_id[:string_contents])
            string_id[:string_contents] = string_nerf[:value]
            string_id[:string_size] = strings_id[:string_contents].length
          end
        end
      end

      # We need to a make the offset be the expected offset + the current length of the section
      string_id_list += Utilities.swap_4(expected_data_offset + string_section.length)
      string_section += Utilities::LEB128.write_uleb128(string_id[:string_size])
      string_section += string_id[:string_contents]
      # Need to have a null byte at the end
      string_section += Utilities.hex_to_char_string "00"
    end

    string_section = Utilities.divisible_4(string_section)

    return string_id_list, string_section
  end

  # Contains indexes into the string section, no offsets used
  def create_type_id_list
    type_id_list = ''

    @sections[:type_id_list].each do |index, type_id|
      type_id_list += Utilities.swap_4(type_id[:index])
    end

    return type_id_list
  end

  # Contains:
  # - index to string section
  # - index to type section
  # - offset into data section for parameters
  def create_proto_id_list(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create a proto_id_list or parameters_section without an expected offset!'
    end
    proto_id_list = ''
    parameters_section = ''

    # TODO : optimize more? We don't need to repeat items, which might be happening
    items = 0

    @sections[:proto_id_list].each do |index, proto_id|
      # index into string section
      proto_id_list += Utilities.swap_4(proto_id[:shorty_index])
      # index into type section
      proto_id_list += Utilities.swap_4(proto_id[:return_type_index])
      # create parameters section, if necessary, for data section
      if(proto_id[:parameters_offset] != 0)
        proto_id_list += Utilities.swap_4(expected_data_offset + parameters_section.length)
        items += 1
        parameters_section += Utilities.swap_4(proto_id[:parameters][:size])
        proto_id[:parameters][:parameter_indexes].each do |parameter_index|
          parameters_section += Utilities.swap_2(parameter_index)
        end
        # Each parameter section should be divisble by 4
        parameters_section = Utilities.divisible_4(parameters_section)
      else
        # if there is no parameters section, we need to fill still fill the rest of our object
        proto_id_list += Utilities.hex_to_char_string "00000000"
      end
    end

    fix_map_item(Type_List, items, expected_data_offset)

    return proto_id_list, parameters_section
  end

  # Contains 2 indexes into the type table and one into the string table
  def create_field_id_list
    field_id_list = ''

    @sections[:field_id_list].each do |index, field_id|
      field_id_list += Utilities.swap_2(field_id[:class_index])
      field_id_list += Utilities.swap_2(field_id[:type_index])
      field_id_list += Utilities.swap_4(field_id[:name_index])
    end

    return field_id_list
  end

  # Contains an index into type table, proto table and the string table
  def create_method_id_list
    method_id_list = ''

    @sections[:method_id_list].each do |index, method_id|
      method_id_list += Utilities.swap_2(method_id[:class_index])
      method_id_list += Utilities.swap_2(method_id[:proto_index])
      method_id_list += Utilities.swap_4(method_id[:name_index])
    end

    return method_id_list
  end

  # class_def_data_block is going to end up containing;
  # -- interfaces
  # -- annotations [ annotation directories, annotation sets and annotation items ]
  # -- class_data_items
  # -- static_values
  # -- code_items
  # -- debug_items
  def create_class_def_items(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create a class_def_items or a class_data_block without an expected offset!'
    end

    class_def_items = ''

    # Create the interface data block and correct offsets
    buffer = create_interface_block(expected_data_offset)

    # Create the annotation data block and correct the offsets
    buffer += create_annotation_block(expected_data_offset + buffer.length)

    # Create the block for the actual class data and correct the offsets
    buffer += create_class_data_block(expected_data_offset + buffer.length)

    # Create the block for the actual static data and correct the offsets
    buffer += create_static_data_block(expected_data_offset + buffer.length)

    @sections[:class_def_items].each do |index, class_def|
      # Index into the type table
      class_def_items += Utilities.swap_4(class_def[:class_index])
      class_def_items += Utilities.swap_4(class_def[:access_flags])
      # Index into the type table
      class_def_items += Utilities.swap_4(class_def[:superclass_index])

      if(class_def[:interfaces_offset] != 0)
        # This offset has already been fixed in the create_interface_block method
        class_def_items += Utilities.swap_4(class_def[:interfaces_offset])
      else
        class_def_items += Utilities.hex_to_char_string "00000000"
      end

      # Index into the string table
      class_def_items += Utilities.swap_4(class_def[:source_file_index])

      if(class_def[:annotations_offset] != 0)
        # This offset has already been fixed in the create_annotation_block method
        class_def_items += Utilities.swap_4(class_def[:annotations_offset])
      else
        class_def_items += Utilities.hex_to_char_string "00000000"
      end

      if(class_def[:class_data_offset] != 0)
        # This offset has already been fixed in the create_class_data_block method
        class_def_items += Utilities.swap_4(class_def[:class_data_offset])
      else
        class_def_items += Utilities.hex_to_char_string "00000000"
      end

      if(class_def[:static_values_offset] != 0)
        # This offset has already been fixed in the create_static_data_block
        class_def_items += Utilities.swap_4(class_def[:static_values_offset])
      else
        class_def_items += Utilities.hex_to_char_string "00000000"
      end
    end

    return class_def_items, buffer
  end

  # Create the interface block and correct the offsets for interfaces
  def create_interface_block(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create an interface data block without an expected offset!'
    end

    buffer = ''
    items = 0
    @sections[:class_def_items].each do |index, class_def|
      # If we have an interface offset already, then we need to modify it to point to
      # the new offset we're going to create
      if(class_def[:interfaces_offset] != 0)
        items += 1
        class_def[:interfaces_offset] = expected_data_offset + buffer.length

        # Write the size
        buffer += Utilities::swap_4(class_def[:interfaces][:size])
        # Write the actual index into the type table
        class_def[:interfaces][:interfaces_indexes].each do |type_index|
          buffer += Utilities::swap_2(type_index)
        end

        buffer = Utilities.divisible_4(buffer)
      end
    end

    # TODO: This is actual part of the type_list which has lots of parameters in it, so it should be added into that section
    get_section_from_map(Type_List)[:size] += items

    return buffer
  end

  # The block being created here is actually just:
  # {
  #   :class_annotation_offset,
  #   :fields_size,
  #   :methods_size,
  #   :parameters_size
  #   methods {
  #     :method_index_offset,
  #     :annotation_offset
  #   }
  # }
  # So every item should be 16 bytes long
  def create_annotation_block(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create an annotation data block without an expected offset!'
    end

    # We need to first create the annotation items
    buffer = create_annotation_item_block(expected_data_offset)
    # We need to first create the class annotation block
    buffer += create_class_annotation_block(expected_data_offset + buffer.length)

    annotation_block_offset = expected_data_offset + buffer.length
    items = 0
    @sections[:class_def_items].each do |index, class_def|
      # Make sure we fix the annotation offset if need be
      if(class_def[:annotations_offset] != 0)
        items += 1
        class_def[:annotations_offset] = expected_data_offset + buffer.length

        buffer += Utilities::swap_4(class_def[:annotations][:annotations_set_offset])
        buffer += Utilities::swap_4(class_def[:annotations][:fields_size])
        buffer += Utilities::swap_4(class_def[:annotations][:methods_size])
        buffer += Utilities::swap_4(class_def[:annotations][:parameters_size])

        # TODO : Write fields

        # TODO : Write methods
        if(class_def[:annotations][:methods_size] != 0)
          class_def[:annotations][:method_annotations].each do |method_annotation|
            buffer += Utilities::swap_4(method_annotation[:method_index])
            buffer += Utilities::swap_4(method_annotation[:annotation_offset])
          end
        end
        # TODO : Write parameters
      end
    end

    fix_map_item(Annotations_Directory_Item, items, annotation_block_offset)

    return buffer
  end

  # The block being created here is actually just:
  # {
  #   :size_annotation_set,
  #   :array_of_offset_of_annotations[size_annotation_set]
  # }
  # So each item is (4 + 4 * number of annotation sets) bytes in length
  def create_class_annotation_block(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create a class annoation data block without an expected offset!'
    end

    buffer = ''
    items = 0
    @sections[:class_def_items].each do |class_def_index, class_def|
      # Not everything will have annotations
      if(!class_def[:annotations].nil? && !class_def[:annotations][:method_annotations].nil?)
        # If we have a class annotation offset already, then we need to modify it to point to
        # the new offset we're going to create
        if(!class_def[:annotations][:method_annotations].nil?)
          class_def[:annotations][:method_annotations].each do |method_annotation|
            if(!method_annotation[:method_sets].nil?)
              items += 1
              method_annotation[:annotation_offset] = expected_data_offset + buffer.length

              buffer += Utilities::swap_4(method_annotation[:method_sets][:annotation_sets_size])
              # These offsets should have already been fixed by the create annotation item block method
              method_annotation[:method_sets][:annotation_offset_items].each do |offset|
                buffer += Utilities::swap_4(offset)
              end
            end
          end
        end
      end
    end

    @sections[:class_def_items].each do |class_def_index, class_def|
      # Not everything will have annotations
      if(!class_def[:annotations].nil?)
        # If we have a class annotation offset already, then we need to modify it to point to
        # the new offset we're going to create
        if(class_def[:annotations][:annotations_set_offset] != 0)
          items += 1
          class_def[:annotations][:annotations_set_offset] = expected_data_offset + buffer.length

          buffer += Utilities::swap_4(class_def[:annotations][:annotation_sets][:annotation_sets_size])
          # These offsets should have already been fixed by the create annotation item block method
          class_def[:annotations][:annotation_sets][:annotation_offset_items].each do |offset|
            buffer += Utilities::swap_4(offset)
          end
        end
      end
    end

    fix_map_item(Annotation_Set_Item, items, expected_data_offset)

    return buffer
  end


  def create_annotation_item_block(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create an annoation item data block without an expected offset!'
    end

    buffer = ''
    items = 0
    # Do method annotations
    @sections[:class_def_items].each do |class_def_index, class_def|
      # Not all class defs have method annotations
      if(!class_def[:annotations].nil? && !class_def[:annotations][:method_annotations].nil?)
        class_def[:annotations][:method_annotations].each do |method_annotation|
          index = 0
          if(!method_annotation[:method_sets].nil?)
            method_annotation[:method_sets][:annotation_items].each do |item|
              items += 1

              # We need to correct the offset we have already, so it matches where we are going to put
              # the actual data at
              method_annotation[:method_sets][:annotation_offset_items][index] = expected_data_offset + buffer.length

              buffer += item[:enum_visibility]
              # Write the index into the type table
              buffer += Utilities::LEB128.write_uleb128(item[:type_index])
              # Write the size of how many encoded values there are
              buffer += Utilities::LEB128.write_uleb128(item[:size])

              # Write the encoded values, but be with name_index in order
              item[:item].sort_by { |itm| itm[:name_index] }.each do |val|
                # Write the name which is an index into the string table
                buffer += Utilities::LEB128::write_uleb128(val[:name_index])

                # Write the actual encoded value, this
                buffer += Utilities::EncodedValue::write_encoded_value(val[:value_type], val[:value_arg], val[:data])
              end
              index += 1
            end
          end
        end
      end
    end

    # Do normal annotations
    @sections[:class_def_items].each do |class_def_index, class_def|
      # Not all class defs have annotations
      if(!class_def[:annotations].nil? && !class_def[:annotations][:annotation_sets].nil?)
        index = 0
        class_def[:annotations][:annotation_sets][:annotation_items].each do |item|
          items += 1

          # We need to correct the offset we have already, so it matches where we are going to put
          # the actual data at
          class_def[:annotations][:annotation_sets][:annotation_offset_items][index] = expected_data_offset + buffer.length

          buffer += item[:enum_visibility]
          # Write the index into the type table
          buffer += Utilities::LEB128.write_uleb128(item[:type_index])
          # Write the size of how many encoded values there are
          buffer += Utilities::LEB128.write_uleb128(item[:size])

          # Write the encoded values, but be with name_index in order
          item[:item].sort_by { |itm| itm[:name_index] }.each do |val|
            # Write the name which is an index into the string table
            buffer += Utilities::LEB128::write_uleb128(val[:name_index])

            # Write the actual encoded value, this
            buffer += Utilities::EncodedValue::write_encoded_value(val[:value_type], val[:value_arg], val[:data])
          end
          index += 1
        end
      end
    end

    buffer = Utilities.divisible_4(buffer)
    fix_map_item(Annotation_Item, items, expected_data_offset)

    return buffer
  end

  def create_class_data_block(expected_data_offset=nil)
    if(expected_data_offset.nil?)
      raise ArgumentError.new 'Unable to create a class data block without an expected offset!'
    end

    # Need to write the code items out first so we know the offsets
    buffer = create_code_block(expected_data_offset)
    items = 0
    class_data_offset = expected_data_offset + buffer.length
    @sections[:class_def_items].each do |class_def_index, class_def|
      # Fix the class data offset, should always be present and need to be changed
      if(class_def[:class_data_offset] != 0)
        items += 1
        class_def[:class_data_offset] = expected_data_offset + buffer.length

        # Go into the actual class data section and rip out the data
        class_data = @sections[:class_data_items][class_def_index]

        # Write the header
        buffer += Utilities::LEB128.write_uleb128(class_data[:header][:static_fields_size])
        buffer += Utilities::LEB128.write_uleb128(class_data[:header][:instance_fields_size])
        buffer += Utilities::LEB128.write_uleb128(class_data[:header][:direct_methods_size])
        buffer += Utilities::LEB128.write_uleb128(class_data[:header][:virtual_methods_size])

        # Write static fields if necessary
        class_data[:static_fields].each do |static_item|
          buffer += Utilities::LEB128.write_uleb128(static_item[:field_index_diff])
          buffer += Utilities::LEB128.write_uleb128(static_item[:access_flags])
        end

        # Write instance fields if necessary
        class_data[:instance_fields].each do |instance_data|
          buffer += Utilities::LEB128.write_uleb128(instance_data[:field_index_diff])
          buffer += Utilities::LEB128.write_uleb128(instance_data[:access_flags])
        end

        # Write direct methods if necessary
        class_data[:direct_methods].each do |direct_method|
          buffer += Utilities::LEB128.write_uleb128(direct_method[:method_index_diff])
          buffer += Utilities::LEB128.write_uleb128(direct_method[:access_flags])
          # This offset should have already been fixed by the create code block method
          buffer += Utilities::LEB128.write_uleb128(direct_method[:code_offset])
        end

        # Write virtual methods if necessary
        class_data[:virtual_methods].each do |virtual_method|
          buffer += Utilities::LEB128.write_uleb128(virtual_method[:method_index_diff])
          buffer += Utilities::LEB128.write_uleb128(virtual_method[:access_flags])
          # This offset should have already been fixed by the create code block method
          buffer += Utilities::LEB128.write_uleb128(virtual_method[:code_offset])
        end
      end
    end

    buffer = Utilities.divisible_4(buffer)

    fix_map_item(Class_Data_Item, items, class_data_offset)

    return buffer
  end

  def create_code_block(expected_output_offset=nil)
    if(expected_output_offset.nil?)
      raise ArgumentError.new 'Unable to create a code block without an expected offset!'
    end

    patch_data = nil
    buffer = ''
    items = 0
    @sections[:class_data_items].each do |class_data_index, class_data|
      # Direct methods
      class_data[:direct_methods].each do |method|
        items += 1

        # See if there is anything to process in reguards to nerfing
        if(!@code_nerf.nil?)
          @code_nerf.each do |code_nerf|
            if(method[:method_index_diff] == code_nerf[:method_index])
              patch_data = code_nerf
            end
          end
        end

        # Correct the offset
        method[:code_offset] = expected_output_offset + buffer.length

        code = method[:code]

        buffer += Utilities.swap_2(code[:registers_size])
        buffer += Utilities.swap_2(code[:ins_size])
        buffer += Utilities.swap_2(code[:outs_size])
        buffer += Utilities.swap_2(code[:tries_size])

        # TODO : After implementing the debug info we should write it out, right now this will strip it
        buffer += Utilities.hex_to_char_string "00000000"

        # Adjust the instruction_size if need be due to patch data
        if(patch_data.nil?)
          buffer += Utilities.swap_4(code[:instruction_size])
        else
          buffer += Utilities.swap_4(code[:instruction_size] + patch_data[:code_length])
          buffer += Utilities.hex_to_char_string patch_data[:code]
        end

        code[:instructions].each do |instruction|
          buffer += Utilities.swap_2(instruction)
        end

        # Ensure the instructions have proper padding
        if(patch_data.nil?)
          if(code[:instruction_size] % 2 != 0)
            buffer += Utilities.hex_to_char_string "0000"
          end
        else
          if((code[:instruction_size] + patch_data[:code_length]) % 2 != 0)
            buffer += Utilities.hex_to_char_string "0000"
          end
        end

        if(code[:tries_size] != 0)
          # Fix (if need be) and write the try blocks
          code[:try_items].each do |try|
            if(patch_data.nil?)
              buffer += Utilities.swap_4(try[:start_addr])
            else
              buffer += Utilities.swap_4(try[:start_addr] + patch_data[:code_length])
            end
            buffer += Utilities.swap_2(try[:instruction_count])
            buffer += Utilities.swap_2(try[:handler_offset])
          end

          # Fix (if need be) and write the handler blocks
          if(code[:handlers_size] != 0)
            buffer += Utilities::LEB128.write_uleb128(code[:handlers_size])

            code[:handlers].each do |handler|
              buffer += Utilities::LEB128.write_uleb128(handler[:size])
              handler[:handler_pairs].each do |pair|
                buffer += Utilities::LEB128.write_uleb128(pair[:type_index])
                if(patch_data.nil?)
                  buffer += Utilities::LEB128.write_uleb128(pair[:address])
                else
                  buffer += Utilities::LEB128.write_uleb128(pair[:address] + patch_data[:code_length])
                end
              end
            end
          end
        end

        # Reset the patch_data object if there was on this interation through
        if(!patch_data.nil?)
          patch_data = nil
        end

        # Ensure we have a properly sized buffer
        buffer = Utilities.divisible_4(buffer)
      end


      # Virtuals methods
      class_data[:virtual_methods].each do |method|

        # It's valid for there to be no code available (interface)
        if(method[:code_offset] != 0)
          items += 1
          # Correct the offset
          method[:code_offset] = expected_output_offset + buffer.length

          code = method[:code]
          buffer += Utilities.swap_2(code[:registers_size])
          buffer += Utilities.swap_2(code[:ins_size])
          buffer += Utilities.swap_2(code[:outs_size])
          buffer += Utilities.swap_2(code[:tries_size])

          # TODO : After implementing the debug info we should write it out, right now this will strip it
          buffer += Utilities.hex_to_char_string "00000000"

          buffer += Utilities.swap_4(code[:instruction_size])

          code[:instructions].each do |instruction|
            buffer += Utilities.swap_2(instruction)
          end

          if(code[:instruction_size] % 2 != 0)
            buffer += Utilities.hex_to_char_string "0000"
          end

          if(code[:tries_size] != 0)
            code[:try_items].each do |try|
              buffer += Utilities.swap_4(try[:start_addr])
              buffer += Utilities.swap_2(try[:instruction_count])
              buffer += Utilities.swap_2(try[:handler_offset])
            end

            if(code[:handlers_size] != 0)
              buffer += Utilities::LEB128.write_uleb128(code[:handlers_size])

              code[:handlers].each do |handler|
                buffer += Utilities::LEB128.write_uleb128(handler[:size])
                handler[:handler_pairs].each do |pair|
                  buffer += Utilities::LEB128.write_uleb128(pair[:type_index])
                  buffer += Utilities::LEB128.write_uleb128(pair[:address])
                end
              end
            end
          end
        end
        buffer = Utilities.divisible_4(buffer)
      end
    end

    fix_map_item(Code_Item, items, expected_output_offset)

    return buffer
  end

  def create_static_data_block(expected_output_offset=nil)
    if(expected_output_offset.nil?)
      raise ArgumentError.new 'Unable to create a static data block without an expected offset!'
    end

    buffer = ''
    items = 0
    @sections[:class_def_items].each do |class_def_index, class_def|
      if(class_def[:static_values_offset] != 0)
        items += 1
        # Fix offset
        class_def[:static_values_offset] = expected_output_offset + buffer.length

        # Write the size of static values
        buffer += Utilities::LEB128.write_uleb128(class_def[:static_values].length)
        class_def[:static_values].each do |item|
          buffer += Utilities::EncodedValue::write_encoded_value(item[:value_type], item[:value_arg], item[:data])
        end
      end
    end

    fix_map_item(Encoded_Array_Item, items, expected_output_offset)

    return buffer
  end

  def create_map
    # FIXME: This isn't right, but it works for right now,
    # it will basically always have the size of what we process
    map = Utilities.swap_4(16) # @map.length)
    @map.sort_by { |hash| hash[:offset] }.each do |item|
      type = item[:type]
      offset = item[:offset]
      unused = item[:unused]
      size = item[:size]

      processed = false
      case type
      when Header_Item
        processed = true
      when String_Id_Item
        processed = true
      when Type_Id_Item
        processed = true
      when Proto_Id_Item
        processed = true
      when Field_Id_Item
        processed = true
      when Method_Id_Item
        processed = true
      when Class_Def_Item
        processed = true
      when Map_List
        processed = true
      when Type_List
        processed = true
      when Annotation_Set_Ref_List
        # Not currently processing
      when Annotation_Set_Item
        processed = true
      when Class_Data_Item
        processed = true
      when Code_Item
        processed = true
      when String_Data_Item
        processed = true
      when Debug_Info_Item
        # Not currently processing
      when Annotation_Item
        processed = true
      when Encoded_Array_Item
        processed = true
      when Annotations_Directory_Item
        processed = true
      else
        Utilities.warn 'Unknown map item was found! This may end badly..'
      end

      if(processed)
        map += Utilities.swap_2(type)
        map += Utilities. swap_2(unused)
        map += Utilities.swap_4(size)
        map += Utilities.swap_4(offset)
      end
    end

    return map
  end

  def get_header_information
    get_magic
    get_checksum
    get_signature
    get_filesize
    get_headersize
    get_endian
    get_section_offsets
  end

  def get_sections
    @sections[:string_id_list] = get_string_id_list
    @sections[:type_id_list] = get_type_id_list
    @sections[:proto_id_list] = get_proto_id_list
    @sections[:field_id_list] = get_field_id_list
    @sections[:method_id_list] = get_method_id_list
    @sections[:class_def_items] = get_class_def_items
    @sections[:class_data_items] = get_class_data_items
  end

  def get_section_from_map(type=nil)
    @map.each do |item|
      if(item[:type] == type)
        return item
      end
    end

    raise ArgumentError.new 'Unable to find specified type of item : [ ' + type.to_s  + ' ] in the map!'
  end

  def fix_map_item(type=nil, size=nil, offset=nil)
    if(type.nil? || size.nil? || offset.nil?)
      raise ArgumentError.new 'To fix a map item, you need to provide a type, size and offset to use!'
    end
    map_item = get_section_from_map type
    map_item[:size] = size
    map_item[:offset] = offset
  end

  # Contains offsets to the struct;
  # {
  #   :string_size,
  #   :string
  # }
  def get_string_id_list
    item = get_section_from_map String_Id_Item
    string_id_list = {}

    (0..item[:size]-1).each do |index|
      offset = read(item[:offset] + (index * 4), 4, 'L').first
      string_size, offset_adjustment = read_uleb128(offset)
      string_contents = read(offset + offset_adjustment, string_size)
      string_id_list[index] = {
        :offset => offset,
        :string_size => string_size,
        :string_contents => string_contents
      }
    end

    return string_id_list
  end

  #
  # Method to resolve the string at a given index for the dex file currently read in
  #
  def resolve_string(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a string with an index of nil!'
    end

    # Check to see if the string actually exists
    if(index >= @sections[:string_id_list].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid string item [ ' + index.to_s + ' ] will result in failure, not trying!'
    end

    return @sections[:string_id_list][index][:string_contents]
  end

  # Contains the index to the descriptor name in the string_id_list
  def get_type_id_list
    item = get_section_from_map Type_Id_Item
    type_id_list = {}

    (0..item[:size]-1).each do |index|
      type_id_list[index] = {
        :index => read(item[:offset] + (index * 4), 4, 'L').first
      }
    end

    return type_id_list
  end

  #
  # Method to resolve the string for a given type_id index for the dex file currently read in
  #
  def resolve_type_id(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a type_id with an index of nil!'
    end

    # Check to see if the type_id actually exists
    if(index >= @sections[:type_id_list].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid type_id index will result in failure, not trying!'
    end

    # Check if the string index returned is valid
    string_index = @sections[:type_id_list][index][:index]
    if(string_index.nil? || string_index > @sections[:string_id_list].length || string_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the type_id_list item [ ' + index.to_s  + ' ] : [ ' + string_index.to_s + ' ]'
    end

    return resolve_string(string_index)
  end

  # Contains the struct;
  # {
  #   :shorty_index,      # index to a string inside the string table
  #   :return_type_index, # ditto
  #   :parameters_offset  # actual file offset
  # }
  def get_proto_id_list
    item = get_section_from_map Proto_Id_Item
    proto_id_list = {}

    (0..item[:size]-1).each do |index|
      proto_id_list[index] = {
        :shorty_index => read(item[:offset] + (index * 12 + 0), 4, 'L').first,
        :return_type_index => read(item[:offset] + (index * 12 + 4), 4, 'L').first,
        :parameters_offset => read(item[:offset] + (index * 12 + 8), 4, 'L').first
      }

      if(proto_id_list[index][:parameters_offset] != 0)
        size = read(proto_id_list[index][:parameters_offset], 4, 'L').first

        parameters = []
        (0..size-1).each do |param_index|
          parameters[param_index] = read(proto_id_list[index][:parameters_offset] + 4 + param_index * 2, 2, 'S').first
        end

        proto_id_list[index][:parameters] = {
          :size => size,
          :parameter_indexes => parameters
        }
      end
    end

    return proto_id_list
  end

  #
  # Method to resolve the strings for a given proto_id index for the dex file currently read in
  #
  def resolve_proto_id(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a proto_id with an index of nil!'
    end

    # Check to see if the proto_d actually exists
    if(index >= @sections[:proto_id_list].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid type_id index will result in failure, not trying!'
    end

    # Check if the string indexes returned is valid
    shorty_index = @sections[:proto_id_list][index][:shorty_index]
    if(shorty_index.nil? || shorty_index > @sections[:string_id_list].length || shorty_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the proto_id_list item [ ' + index.to_s
      +  ' ] shorty_index field : [ ' + shorty_index.to_s + ' ]'
    end

    return_type_index = @sections[:proto_id_list][index][:return_type_index]
    if(return_type_index.nil? || return_type_index > @sections[:string_id_list].length || return_type_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the proto_id_list item [ ' + index.to_s
      +  ' ] return_type_index field : [ ' + return_type_index.to_s + ' ]'
    end

    params = @sections[:proto_id_list][index][:parameters]
    if(!params.nil?)
      parameters = ""
      (0..params[:size]-1).each do |param|
        parameters += resolve_type_id(params[:parameter_indexes][param])
        if(param != params[:size]-1)
          parameters += ", "
        end
      end
    end

    parameters_offset = @sections[:proto_id_list][index][:parameters_offset]

    return {
      :shorty => resolve_string(shorty_index),
      :return_type => resolve_type_id(return_type_index),
      :parameters_offset => parameters_offset,
      :parameters => parameters
    }
  end

  # Contains the struct;
  # {
  #   :class_index, # index to type
  #   :type_index,  # index to type
  #   :name_index   # index to string
  # }
  def get_field_id_list
    item = get_section_from_map Field_Id_Item
    field_id_list = {}

    (0..item[:size]-1).each do |index|
      field_id_list[index] = {
        :class_index => read(item[:offset] + (index * 8 + 0), 2, 'S').first,
        :type_index => read(item[:offset] + (index * 8 + 2), 2, 'S').first,
        :name_index => read(item[:offset] + (index * 8 + 4), 4, 'L').first
      }
    end

    return field_id_list
  end

  #
  # Method to resolve the strings for a given field_id_list index for the dex file currently read in
  #
  def resolve_field_id(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a field_id with an index of nil!'
    end

    # Check to see if the type_id actually exists
    if(index >= @sections[:field_id_list].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid field_id index will result in failure, not trying!'
    end

    # Check if the indexes returned is valid
    class_index = @sections[:field_id_list][index][:class_index]
    if(class_index.nil? || class_index > @sections[:type_id_list].length || class_index < 0)
      raise ArgumentError.new 'Invalid type_id index was returned from the field_id_list item [ ' + index.to_s
      +  ' ] class_index field : [ ' + class_index.to_s + ' ]'
    end

    type_index = @sections[:field_id_list][index][:type_index]
    if(type_index.nil? || type_index > @sections[:type_id_list].length || type_index < 0)
      raise ArgumentError.new 'Invalid type_id index was returned from the field_id_list item [ ' + index.to_s
      +  ' ] type_index field : [ ' + type_index.to_s + ' ]'
    end

    name_index = @sections[:field_id_list][index][:name_index]
    if(name_index.nil? || name_index > @sections[:string_id_list].length || name_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the field_id_list item [ ' + index.to_s
      +  ' ] name_index field : [ ' + name_index.to_s + ' ]'
    end

    return {
      :class => resolve_type_id(class_index),
      :type => resolve_type_id(type_index),
      :name => resolve_string(name_index)
    }
  end

  # Contains the struct
  # {
  #   :class_index, # index to type
  #   :proto_index, # index to proto
  #   :name_index   # index to string
  # }
  def get_method_id_list
    item = get_section_from_map Method_Id_Item
    method_id_list = {}

    (0..item[:size]-1).each do |index|
      method_id_list[index] = {
        :class_index => read(item[:offset] + (index * 8 + 0), 2, 'S').first,
        :proto_index => read(item[:offset] + (index * 8 + 2), 2, 'S').first,
        :name_index => read(item[:offset] + (index * 8 + 4), 4, 'L').first
      }
    end

    return method_id_list
  end

  #
  # Method to resolve the method at a given index for the dex file currently read i
  #
  def resolve_method_id(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a method_id with an index of nil!'
    end

    # Check to see if the method_id actually exists
    if(index >= @sections[:method_id_list].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid method_id index will result in failure, not trying!'
    end

    # Check if the indexes returned is valid
    class_index = @sections[:method_id_list][index][:class_index]
    if(class_index.nil? || class_index > @sections[:type_id_list].length || class_index < 0)
      raise ArgumentError.new 'Invalid type_id index was returned from the method_id_list item [ ' + index.to_s
      +  ' ] class_index field : [ ' + class_index.to_s + ' ]'
    end

    proto_index = @sections[:method_id_list][index][:proto_index]
    if(proto_index.nil? || proto_index > @sections[:proto_id_list].length || proto_index < 0)
      raise ArgumentError.new 'Invalid proto_id index was returned from the method_id_list item [ ' + index.to_s
      +  ' ] proto_index field : [ ' + proto_index.to_s + ' ]'
    end

    name_index = @sections[:method_id_list][index][:name_index]
    if(name_index.nil? || name_index > @sections[:string_id_list].length || name_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the method_id_list item [ ' + index.to_s
      +  ' ] class_index field : [ ' + name_index.to_s + ' ]'
    end

    return {
      :class => resolve_type_id(class_index),
      :proto => resolve_proto_id(proto_index),
      :name => resolve_string(name_index)
    }
  end

  # Contains the struct
  # {
  #   :class_index, # index to type
  #   :access_flags, # enum of type ACCESS_FLAGS
  #   :superclass_index, # index to type
  #   :interfaces_offset, # offset to interface list
  #   :source_file_idx, # index to string (represents the original source.java file name)
  #   :annotations_offset, # offset to the annotations
  #   :class_data_offset, # offset to the class data
  #   :static_values_offset, # offset to the static values used by this class
  # }
  def get_class_def_items
    item = get_section_from_map Class_Def_Item
    class_def_list = {}

    (0..item[:size]-1).each do |index|
      # Get the easy parts
      interfaces_offset = read(item[:offset] + (index * 32 + 12), 4, 'L').first
      annotations_offset = read(item[:offset] + (index * 32 + 20), 4, 'L').first
      class_data_offset =  read(item[:offset] + (index * 32 + 24), 4, 'L').first
      static_values_offset = read(item[:offset] + (index * 32 + 28), 4, 'L').first

      class_def_list[index] = {
        :class_index => read(item[:offset] + (index * 32 + 0), 4, 'L').first,
        :access_flags => read(item[:offset] + (index * 32 + 4), 4, 'L').first,
        :superclass_index => read(item[:offset] + (index * 32 + 8), 4, 'L').first,
        :interfaces_offset => interfaces_offset,
        :source_file_index => read(item[:offset] + (index * 32 + 16), 4, 'L').first,
        :annotations_offset => annotations_offset,
        :class_data_offset => class_data_offset,
        :static_values_offset => static_values_offset
      }

      # Get the interfaces
      if(interfaces_offset != 0)
        size = read(interfaces_offset, 4, 'L').first
        interfaces = []
        (0..size-1).each do |interface_index|
          interfaces << read(interfaces_offset + 4 + interface_index * 2, 2, 'S').first
        end

        class_def_list[index][:interfaces] = {
          :size => size,
          :interfaces_indexes => interfaces
        }
      end

      # Get the annotations
      if(annotations_offset != 0)
        annotation_sets_offset = read(annotations_offset, 4, 'L').first
        fields_size = read(annotations_offset + 4, 4, 'L').first
        methods_size = read(annotations_offset + 8, 4, 'L').first
        parameters_size = read(annotations_offset + 12, 4, 'L').first

        class_def_list[index][:annotations] = {
          :annotations_set_offset => annotation_sets_offset,
          :fields_size => fields_size,
          :methods_size => methods_size,
          :parameters_size => parameters_size
        }

        # TODO : Process fields
        # This might not actually be necessary though?

        # Process Methods
        if(methods_size != 0)
          # Read method annotations
          method_annotations = []
          (0..methods_size-1).each do |method_annotation_index|
            method_index = read(annotations_offset + 16 + (method_annotation_index * 8), 4, 'L').first
            annotation_offset  = read(annotations_offset + 20 + (method_annotation_index * 8), 4, 'L').first

            # TODO: This might need to be an array to accept more than one method annotation
            # Read method annotation data
            method_sets = nil #[]
            (0..methods_size-1).each do |method_idx|
              size, annotation_sets, annotation_items = get_annotation_item(annotation_offset)
              method_sets = {
                :annotation_sets_size => size,
                :annotation_offset_items => annotation_sets,
                :annotation_items => annotation_items
              }
            end

            method_annotations << {
              :method_index => method_index,
              :annotation_offset => annotation_offset,
              :method_sets => method_sets
            }
          end

          class_def_list[index][:annotations][:method_annotations] = method_annotations
        end
        # TODO : Process Parameters

        if(annotation_sets_offset != 0)
          size, annotation_sets, annotation_items = get_annotation_item(annotation_sets_offset)

          class_def_list[index][:annotations][:annotation_sets] = {
            :annotation_sets_size => size,
            :annotation_offset_items => annotation_sets,
            :annotation_items => annotation_items
          }
        end
      end

      # Get static values
      # {
      #   uleb128 size,
      #   static_item[size] {
      #     encoded_value values
      #   }
      # }
      if(class_def_list[index][:static_values_offset] != 0)
        static_values = []
        offset = 0
        static_values_size, offset_fix = read_uleb128(class_def_list[index][:static_values_offset] + offset)
        offset += offset_fix

        (0..static_values_size-1).each do |static_index|
          value_type, value_arg, data, offsetfix = read_encoded_value(class_def_list[index][:static_values_offset] + offset)
          offset += offsetfix
          static_values[static_index] = {
            :value_type => value_type,
            :value_arg => value_arg,
            :data => data
          }
        end

        class_def_list[index][:static_values] = static_values
      end
    end

    return class_def_list
  end

  def get_annotation_item(annotation_items_offset=nil)
    sets_size = read(annotation_items_offset, 4, 'L').first
    annotation_sets = []
    (0..sets_size-1).each do |annotation_index|
      annotation_sets[annotation_index] = read(annotation_items_offset + 4 + annotation_index * 4, 4, 'L').first
    end

    # Process actual annotation_items
    annotation_items = []
    (0..sets_size-1).each do |annotation_item_index|
      offset = 1
      enum_visibility = read(annotation_sets[annotation_item_index], 1)
      type_index, offset_fix = read_uleb128(annotation_sets[annotation_item_index] + offset)
      offset += offset_fix
      size, offset_fix = read_uleb128(annotation_sets[annotation_item_index] + offset)
      offset += offset_fix

      items = []
      (0..size-1).each do |element_index|
        name_index, offset_fix = read_uleb128(annotation_sets[annotation_item_index] + offset)
        offset += offset_fix
        value_type, value_arg, data, offset_fix = read_encoded_value(annotation_sets[annotation_item_index] + offset)
        offset += offset_fix
        items[element_index] = {
          :name_index => name_index,
          :value_type => value_type,
          :value_arg => value_arg,
          :data => data
        }
      end

      annotation_items[annotation_item_index] = {
        :enum_visibility => enum_visibility,
        :type_index => type_index,
        :size => size,
        :item => items
      }
    end

    return sets_size, annotation_sets, annotation_items
  end

  #
  # Method to resolve the class definition at a given index for the dex file currently read i
  #
  # TODO : Finishing resolving offsets?
  def resolve_class_def(index=nil)
    if(index.nil?)
      raise ArgumentError.new 'Unable to resolve a method_id with an index of nil!'
    end

    # Check to see if the class def actually exists
    if(index >= @sections[:class_def_items].length || index < 0)
      raise ArgumentError.new 'Attempting to get an invalid class_def item will result in failure, not trying!'
    end

    # Check if the indexes returned is valid
    class_index = @sections[:class_def_items][index][:class_index]
    if(class_index.nil? || class_index > @sections[:type_id_list].length || class_index < 0)
      raise ArgumentError.new 'Invalid type_id index was returned from the class_def_items item [ ' + index.to_s
      +  ' ] class_index field : [ ' + class_index.to_s + ' ]'
    end

    # TODO : map back to human readable flags?
    access_flags = @sections[:class_def_items][index][:access_flags]

    superclass_index = @sections[:class_def_items][index][:superclass_index]
    if(superclass_index.nil? || superclass_index > @sections[:type_id_list].length || superclass_index < 0)
      raise ArgumentError.new 'Invalid type_id index was returned from the class_def_items item [ ' + index.to_s
      +  ' ] superclass_index field : [ ' + superclass_index.to_s + ' ]'
    end

    # Resolve the interface types -- having no interfaces is valid
    interfaces = []
    if(@sections[:class_def_items][index][:interfaces] != nil)
      # TODO : should be able to replace this with a .each do and a inferfacter <<
      (0..@sections[:class_def_items][index][:interfaces][:size]-1).each do |i|
        type_id_index = @sections[:class_def_items][index][:interfaces][:interfaces_indexes][i]
        if(type_id_index.nil? || type_id_index > @sections[:type_id_list].length || type_id_index < 0)
          raise ArgumentError.new 'Invalid type_id index was returned from the class_def_items item [ ' + index.to_s
                + ' ] interface type_id_index field : [ ' + type_id_index.to_s + ' ]'
        end
        interfaces[i] = resolve_type_id(@sections[:class_def_items][index][:interfaces][:interfaces_indexes][i])
      end
    end

    # Resolve the string for the source file -- it's possible there is none though
    source_file_index = @sections[:class_def_items][index][:source_file_index]
    if(source_file_index.nil? || source_file_index > @sections[:string_id_list].length || source_file_index < 0)
      raise ArgumentError.new 'Invalid string_id index was returned from the class_def_items item [ ' + index.to_s
            +  ' ] source_file_index field : [ ' + source_file_index.to_s + ' ]'
    end

    # Resolve the annotation sets - it's possible there is none though
    annotation_items = []
    if(!@sections[:class_def_items][index][:annotations].nil? && !@sections[:class_def_items][index][:annotations][:annotation_sets].nil?)
      @sections[:class_def_items][index][:annotations][:annotation_sets][:annotation_items].each do |annotation_item|

        type_id_index = annotation_item[:type_index]
        if(type_id_index.nil? || type_id_index > @sections[:type_id_list].length || type_id_index < 0)
          raise ArgumentError.new 'Invalid type_id index was returned from the class_def_items item [ ' + index.to_s
          + ' ] annotation item [ ' + set_index.to_s + ' ] which has a type_id_index field : [ ' + type_id_index.to_s + ' ]'
        end

        items = []
        # Resolve the items contains in the annotation sets
        annotation_item[:item].each do |item|
          name_index = item[:name_index]
          if(type_id_index.nil? || type_id_index > @sections[:type_id_list].length || type_id_index < 0)
            raise ArgumentError.new 'Invalid string_id index was returned from the class_def_items item [ ' + index.to_s
            + ' ] annotation item [ ' + set_index.to_s + ' ] item index [ ' + item_index.to_s
            + ' ] which has a string_id_index field : [ ' + type_id_index.to_s + ' ]'
          end

          items << {
            :name => resolve_string(name_index),
            :type => Utilities::EncodedValue.resolve_type(item[:value_type]),
            :arg => item[:value_arg],
            :data => item[:data]
          }
      end

        # TODO : Resolve the num_visibility back to human readable flags
        annotation_items << {
          :enum_visibility => annotation_item[:enum_visibility],
          :type => resolve_type_id(type_id_index),
          :items => items
        }
      end

      # Resolve base annotation
      annotations = {
        :fields_size => @sections[:class_def_items][index][:annotations][:fields_size],
        :methods_size => @sections[:class_def_items][index][:annotations][:methods_size],
        :parameters_size => @sections[:class_def_items][index][:annotations][:parameters_size],
        :annotation_items=> annotation_items
      }
    end

    # TODO : resolve this? YES nothing else is resolving this
    class_data_offset = @sections[:class_def_items][index][:class_data_offset]

    # Resolve static values
    static_values = []
    if(@sections[:class_def_items][index][:static_values_offset] != 0)
      @sections[:class_def_items][index][:static_values].each do |static_value|
        static_values << {
          :type => Utilities::EncodedValue.resolve_type(static_value[:value_type]),
          :arg => static_value[:value_arg],
          :data => static_value[:data]
        }
      end
    end

    return {
      :class => resolve_type_id(class_index),
      :access_flags => access_flags,
      :superclass => resolve_type_id(superclass_index),
      :interfaces => interfaces,
      :source_file => resolve_string(source_file_index),
      :annotations => annotations,
      :class_data_offset => class_data_offset,
      :static_values => static_values
    }
  end

  #  Data structue for class_data_items is a bit interesting, the header is using
  #  Unsigned LEB128 (lower endian base 128) to store a large number in one byte.
  #  The rest of the structures will not exist if the size is zero.
  #
  #  {
  #    header {
  #      leb128 static_fields_size,
  #      leb128 instance_fields_size,
  #      leb128 direct_methods_size,
  #      leb128 virtual_methods_size
  #    }
  #    static_fields {
  #      fieldIdx,
  #      accessFlags
  #    }
  #    instance_fields {
  #      fieldIdx,
  #      accessFlags
  #    }
  #    direct_methods {
  #      methodIdx,
  #      accessFlags,
  #      codeOffset,
  #      codeItem {
  #        ushort2 registers_size,
  #        ushort2 ins_size,
  #        ushort2 outs_size,
  #        ushort2 tries_size,
  #        uint4 debug_info_offset,
  #        debug_info {
  #          uleb128 line_start,
  #          uleb128 parameters_size,
  #          uleb128 debug_opcode[] // Read opcodes until you hit DBG_END_SEQUENCE (0x00)
  #        },
  #        uint4 instruction_size,
  #        ushort2 instructions[instruction_size],
  #        // the try/catch/handler stuff is all options below this point
  #        ushort2 padding, // this reads as "optional" in the instruction set - looks like it needs to be used
  #                         // because we can't end without the section being % 4 in size
  #        try_item[tries_size] {
  #          uint4 start_addr,
  #          ushort2 instruction_count,
  #          ushort2 handler_offset
  #        },
  #        uleb128 handlers_size,
  #        handlers[handlers_size] {
  #          exception_size,
  #          exception[exception_size] {
  #            uleb128 type_idx,
  #            uleb128 address
  #          }
  #        }
  #      }
  #    }
  #    virtual_methods {
  #      methodIdx,
  #      accessFlags,
  #      codeOffset,
  #      codeItem {
  #        # The same as the struct above
  #      }
  #    }
  #  }
  def get_class_data_items
    item = get_section_from_map Class_Data_Item
    class_data_list = {}

    extra_offset = 0
    offset = item[:offset]
    (0..item[:size]-1).each do |index|
      class_data_list[index] = {
        :header => {
        },
        :static_fields => [],
        :instance_fields => [],
        :direct_methods => [],
        :virtual_methods => []
      }

      # Read in the size of fields for usage below
      class_data_list[index][:header][:static_fields_size], extra_offset = read_uleb128(offset)
      offset += extra_offset
      class_data_list[index][:header][:instance_fields_size], extra_offset = read_uleb128(offset)
      offset += extra_offset
      class_data_list[index][:header][:direct_methods_size], extra_offset = read_uleb128(offset)
      offset += extra_offset
      class_data_list[index][:header][:virtual_methods_size], extra_offset = read_uleb128(offset)
      offset += extra_offset

      # Get static fields data
      (0..class_data_list[index][:header][:static_fields_size]-1).each do |item|
        class_data_list[index][:static_fields][item] = {}

        class_data_list[index][:static_fields][item][:field_index_diff], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:static_fields][item][:access_flags], extra_offset = read_uleb128(offset)
        offset += extra_offset
      end

      # Get instance fields data
      (0..class_data_list[index][:header][:instance_fields_size]-1).each do |item|
        class_data_list[index][:instance_fields][item] = {}

        class_data_list[index][:instance_fields][item][:field_index_diff], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:instance_fields][item][:access_flags], extra_offset = read_uleb128(offset)
        offset += extra_offset
      end

      # Get direct methods data
      (0..class_data_list[index][:header][:direct_methods_size]-1).each do |item|
        class_data_list[index][:direct_methods][item] = {}

        class_data_list[index][:direct_methods][item][:method_index_diff], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:direct_methods][item][:access_flags], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:direct_methods][item][:code_offset], extra_offset = read_uleb128(offset)
        offset += extra_offset

        # Get and append the methods actual data
        get_method_data(class_data_list[index][:direct_methods][item])
      end

      # Get virtual methods size
      (0..class_data_list[index][:header][:virtual_methods_size]-1).each do |item|
        class_data_list[index][:virtual_methods][item] = {}

        class_data_list[index][:virtual_methods][item][:method_index_diff], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:virtual_methods][item][:access_flags], extra_offset = read_uleb128(offset)
        offset += extra_offset
        class_data_list[index][:virtual_methods][item][:code_offset], extra_offset = read_uleb128(offset)
        offset += extra_offset

        # Get and append the methods actual data
        get_method_data(class_data_list[index][:virtual_methods][item])
      end
    end

    return class_data_list
  end

  def get_method_data(method=nil)
    if(method.nil?)
      raise ArgumentError.new 'Unable to get method data for a nil object!'
    end

    offset = method[:code_offset]
    code = method[:code] = {}
    if(offset != 0)
      # Number of registers used
      code[:registers_size] = read(offset + 0, 2, 'S').first
      # Number of registers in
      code[:ins_size] = read(offset + 2, 2, 'S').first
      # Number of registers out
      code[:outs_size] = read(offset + 4, 2, 'S').first
      # Number of try/catch handlers
      code[:tries_size] = read(offset + 6, 2, 'S').first

      # Offset for debug info
      code[:debug_info_offset] = read(offset + 8, 4, 'L').first
      get_debug_info(code)

      # Number of instructions to read
      code[:instruction_size] = read(offset + 12, 4, 'L').first

      code[:instructions] = []
      # Read the amount of instructions in
      (0..code[:instruction_size]-1).each do |index|
        code[:instructions] << read((offset + 16) + index * 2, 2, 'S').first
      end

      offset = offset + 16 + code[:instruction_size] * 2

      # If the amount of instructions is not % 2 safe then we should have padding
      if(code[:instruction_size] % 2 != 0)
        code[:padding] = read(offset, 2, 'S').first
        offset += 2
        if(code[:padding] != 0)
          code_offset = sprintf("%02x", method[:code_offset])
          padding = sprintf("%02x", code[:padding])
          Utilities.warn 'Hit some odd/unexpected padding inside a method @ [ ' + code_offset + ' ] : [ ' + padding + ' ]'
        end
      else
        code[:padding] = nil
      end

      # Read tries if present
      if(code[:tries_size] != 0)
        code[:try_items] = []
        (0..code[:tries_size]-1).each do |index|
          code[:try_items] << {
            :start_addr => read(offset, 4, 'L').first,
            :instruction_count => read(offset + 4, 2, 'S').first,
            :handler_offset => read(offset + 6, 2, 'S').first
          }
          offset += 8
        end

        # Read number of handlers present
        code[:handlers_size], offset_adjustment = read_uleb128(offset)
        offset += offset_adjustment
        # Read handlers if present (only if tries are there as well!)
        if(code[:handlers_size] != 0)
          code[:handlers] = []
          (0..code[:handlers_size]-1).each do |index|
            size, offset_adjustment = read_uleb128(offset)
            offset += offset_adjustment
            pairs = []
            (0..size-1).each do |pair_index|
              type_index, offset_adjustment = read_uleb128(offset)
              offset += offset_adjustment
              addr, offset_adjustment = read_uleb128(offset)
              offset += offset_adjustment
              pairs << {
                :type_index => type_index,
                :address => addr
              }
            end
            code[:handlers] << {
              :size => size,
              :handler_pairs => pairs
            }
          end
        end
      end
    end
  end

  # TODO : This needs to be finished in order to support debug info
  def get_debug_info(code_object=nil)
    if(code_object.nil?)
      raise ArgumentError.new 'Unable to get debug information from a nil code object!'
    end

    offset = code_object[:debug_info_offset]
    if(offset != 0)
      debug = code_object[:debug_info] = {}

      debug[:line_start], offset_adjustment = read_uleb128(offset)
      offset += offset_adjustment
      debug[:parameters_size], offset_adjustment = read_uleb128(offset)
      offset += offset_adjustment

      # Read the parameter string ids
      if(debug[:parameters_size] != 0)
        parameters = []
        (0..debug[:parameters_size]-1).each do |index|
          parameter, offset_adjustment = read_uleb128(offset)
          offset += offset_adjustment
          parameters << parameter
        end
      end

      # Read the debug data - ends with DBG_END_SEQUENCE (0x00)
    end
  end

  def resolve_class_data(index=nil)
    # TODO : Finish this along with chaining it into the class_def resolver
  end

  def get_map_information
    items = read(get_header('map_offset'), 4, 'L').first

    @original_map_length = items * 12 + 4

    offset = get_header('map_offset') + 4

    @map = []
    (0..items-1).each do |index|
      unused = read(offset + (index * 12 + 2), 2, 'S').first
      @map << {
        :type => read(offset + (index * 12 + 0), 2, 'S').first,
        :unused => unused,
        :size => read(offset + (index * 12 + 4), 4, 'L').first,
        :offset => read(offset + (index * 12 + 8), 4, 'L').first,
      }

      if(unused != 0)
        Utilities.warn 'The unused bits of the map item are set to something!'
      end
    end
  end

  def get_magic
    @header[:magic] = read(0, 4, 'H*')
    if(DEX_MAGIC.unpack('H*') == @header[:magic])
      @dex_type = DEX
    elsif(DEX_OPT_MAGIC.unpack('H*') == @header[:magic])
      @dex_type = ODEX
    elsif(DEX_DEP_MAGIC.unpack('H*') == @header[:magic])
      raise ArgumentError.new 'File appears to have "DEPS_MAGIC" though I don\'t know how to handle that!'
    else
      raise ArgumentError.new 'Does not appear to be a supported dex file, magic bits where [ ' + magic.to_s  + ' ]'
    end

    @header[:magic_ver] = read(4, 4, 'H*')
    if(@dex_type == DEX)
      if(DEX_MAGIC_VERS_35.unpack('H*') == @header[:magic_ver])
        @dex_ver = DEX_VER_35
      elsif(DEX_MAGIC_VERS_36.unpack('H*') == @header[:magic_ver])
        @dex_Ver = DEX_VER_36
      end
    else
      if(DEX_OPT_MAGIC_VERS.unpack('H*') == @header[:magic_ver])
        @dex_Ver = DEX_OPT_VER_36
      end
    end

    if(@dex_ver.nil?)
      raise ArgumentError.new 'Does not appear to be a supported dex file version type, version is [ ' + version.to_s + ' ]'
    end
  end

  def get_checksum
    @header[:checksum] = read(8, 4, 'L').first
    if(@verbose)
      adler = generate_checksum
      if(@header[:checksum] != adler)
        Utilities.warn "Checksum does not appear to be correct!\n\t  Expected [ 0x" + get_header('checksum').to_s(16)  + " ] but got [ 0x" + adler.to_s(16) + " ]"
      else
        Utilities.info 'Checksum appears to be fine! [ 0x' + @header[:checksum].to_s(16) + ' ]'
      end
    end
  end

  def generate_checksum
    Zlib.adler32(read(12, File.size?(@dex_file), nil), nil).to_i
  end

  def get_signature
    @header[:signature] = read(12, 20, 'H*').first
    if(@verbose)
      sig = generate_signature
      if(@header[:signature] != sig)
        Utilities.warn "Signature does not appear to be correct!\n\t  Expected [ 0x" + get_header('signature')  + " ] but got [ 0x" + sig + " ]"
      else
        Utilities.info 'Signature checks out! [ 0x' + @header[:signature] + ' ]'
      end
    end
  end

  def generate_signature
    Digest::SHA1.hexdigest(read(32, File.size?(@dex_file), nil))
  end

  def get_filesize
    @header[:file_size] = read(32, 4, 'L').first
    if(@verbose)
      if(@header[:file_size] < File.size?(@dex_file))
        raise ArgumentError.new "File size noted in the header is smaller than the actual file size!\n\t  Expected [ " + @header[:file_size].to_s + " ] but got [ " + File.size(@dex_file).to_s + " ]"
      elsif(@header[:file_size] != File.size?(@dex_file))
        Utilities.warn "File size noted in the header is not equal to the actual file size\n\t  Expected [ " + @header[:file_size].to_s + " ] but got [ " + File.size(@dex_file).to_s + " ]"
      else
        Utilities.info 'File size checks out! [ ' + @header[:file_size].to_s + ' ]'
      end
    end
  end

  def get_headersize
    @header[:header_size] = read(36, 4, 'L').first
    if(@verbose)
      if(@header[:header_size] != DEFAULT_HEADER_SIZE)
        Utilities.warn 'Header size is not the expected value! [ 0x' + @header[:header_size].to_s(16) + ' ]'
      else
        Utilities.info 'Header size checks out! [ 0x' + @header[:header_size].to_s(16) + ' ]'
      end
    end
  end

  def get_endian
    @header[:endian] = read(40, 4, 'L').first
    if(@verbose)
      if(@header[:endian] != ENDIAN_TAG)
        Utilities.warn 'Endian tag is not as expected!'
      else
        Utilities.info 'Endian tag checks out! [ 0x' + @header[:endian].to_s(16) + ' ]'
      end
    end
  end

  def get_section_offsets
    @header[:link_size] = read(44, 4, 'L').first
    @header[:link_offset] = read(48, 4, 'L').first

    if(@verbose)
      if(@header[:link_size] != 0 || @header[:link_offset] != 0)
        Utilities.warn 'Link section appears to have been messed with'
      else
        Utilities.info 'Link section is empty. (normal)'
      end
    end

    @header[:map_offset] = read(52, 4, 'L').first
    @header[:string_ids_size] = read(56, 4, 'L').first
    @header[:string_ids_offset] = read(60, 4, 'L').first
    @header[:type_ids_size] = read(64, 4, 'L').first
    @header[:type_ids_offset] = read(68, 4, 'L').first
    @header[:proto_ids_size] = read(72, 4, 'L').first
    @header[:proto_ids_offset] = read(76, 4, 'L').first
    @header[:field_ids_size] = read(80, 4, 'L').first
    @header[:field_ids_offset] = read(84, 4, 'L').first
    @header[:method_ids_size] = read(88, 4, 'L').first
    @header[:method_ids_offset] = read(92, 4, 'L').first
    @header[:class_defs_size] = read(96, 4, 'L').first
    @header[:class_defs_offset] = read(100, 4, 'L').first
    @header[:data_size] = read(104, 4, 'L').first
    @header[:data_offset] = read(108, 4, 'L').first
  end

  def nerf_link_section
    @header[:link_size] = rand(@header[:file_size])
    @header[:link_offset] = @header[:file_size] - @header[:link_size]
    if(@verbose)
      Utilities.info "Nerfing link section information; \n\tlink size : " + @header[:link_size].to_s + " link offset : " + @header[:link_offset].to_s
    end
  end

  def read(offset=nil, length=nil, unpack=nil)
    @dex_file.seek(offset, IO::SEEK_SET)
    result = @dex_file.read(length)
    if(!unpack.nil?)
      result = result.unpack(unpack)
    end

    return result
  end

  def read_uleb128(offset)
    return Utilities::LEB128.read_unsigned_leb128(read(offset, 5, 'H*').first)
  end

  # TODO : Fix this for better recursion
  # Helper method, hopefuly 20 characters is enough for arrays/recursion we might do
  def read_encoded_value(offset)
    return Utilities::EncodedValue.read_encoded_value(read(offset, 20, 'H*').first)
  end

  def set_header(field=nil, value=nil)
    @header.each_key do |key|
      if(key.to_s == field)
        @header[key] = value
      end
    end
  end

  def get_header(field=nil)
    @header.each_key do |key|
      if(key.to_s == field)
        return @header[key]
      end
    end
    return nil
  end

end
