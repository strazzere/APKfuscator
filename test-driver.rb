#!/usr/bin/env ruby
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

require 'apkfuscator.rb'

dex_file = DexFile.new 'resources/release-crackme-classes.dex', false

test_resolvers = false
if(test_resolvers)

  # attempt to resolve every string
  (0..129).each do |string|
    dex_file.resolve_string string
  end

  # every type
  (0..35).each do |type|
    dex_file.resolve_type_id type
  end

  # every proto
  (0..25).each do |proto|
    dex_file.resolve_proto_id proto
  end

  # every field
  (0..18).each do |field|
    dex_file.resolve_field_id field
  end

  # every method
  (0..40).each do |method|
    dex_file.resolve_method_id method
  end

  # every class
  (0..8).each do |class_def|
    dex_file.resolve_class_def class_def
  end

  #dex_file.get_class_data_items
  # every class data
  (0..8).each do |class_data|
    #pp dex_file.resolve_class_data class_data
  end
end

test_nerf_header_size = false
if(test_nerf_header_size)
  dex_file.nerf_header_size 112
  dex_file.save_modified 'header_size_test'
  # reload the nerf test to ensure we didn't kill something
  DexFile.new 'header_size_test', true
end

test_nerf_code = true
if(test_nerf_code)

  code = '1201' # load 0 into v1
  code += '3801' + '0300' # a jump which should never succeed so three bytes will be skipped
  code += '1a00' + 'FF00' # const-string @string_table 255
  #code += '2600' + '0300' + '0000'
  #code += '0003' + '0100' + '4E01' + '0000' + '120E'
  #code += 'FFFF' #'1251' # 'FFFF' # bad opcodes

  code_to_nerf = {
    :code => code,
    :code_length => 5,
    :method_index => 32
  }
  dex_file.nerf_code_section code_to_nerf
  dex_file.save_modified 'code_nerf.test'
  DexFile.new 'code_nerf.test', true
end

test_nerf_string = false
if(test_nerf_string)
  string_to_nerf = {
    :string => "Ldont/decompile/me/BuildConfig;",
    :value => "Ldont/decompile/me/BuildConfig_why_would_you_go_and_do_a_thing_like_this_that_just_isnt_cool_man_this_application_even_says_in_its_package_name_not_to_decompile_it_have_you_no_manners_______someday_someone_might_decompile_you_then_youll_understand_the_feelings_this_poor_little_dex_file_is_feeling_right_at_this_moment;"
  }
  dex_file.nerf_string_section string_to_nerf
  dex_file.save_modified 'string_nerf.test'
  DexFile.new 'string_nerf.test', true
end

test_class_injection = false
if(test_class_injection)
  dex_file = DexFile.new 'resources/apkcrypt.dex', true
  dex_file.nerf_header_size 6880, 'resources/release-crackme-classes.dex'
  dex_file.save_modified 'dexception-injection.test'
  DexFile.new 'dexception-injection.test', true
end

test_nerf_link_section = false
if(test_nerf_link_section)
  dex_file.nerf_header_size 112
  dex_file.nerf_link_section
  dex_file.save_modified 'linked_section_nerf.test'
  # reload the nerf test to ensure we didn't kill something
  DexFile.new 'linked_section_nerf.test', true
end
