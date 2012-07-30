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
require '../lib/utilities.rb'

#
# Lightweight testing w/o a framework to some simple test cases...
#

module Apkfuscator
  class Tests

    def initialize
      if(read_encoded_value_type_method_test)
        puts 'read_encoded_value_type_method_test passed'
      else
        puts 'read_encoded_value_type_method_test failed'
      end

      if(read_encoded_value_type_null_test)
        puts 'read_encoded_value_type_null_test passed'
      else
        puts 'read_encoded_value_type_null_test failed'
      end

      if(read_encoded_value_type_int_test)
        puts 'read_encoded_value_type_int_test passed'
      else
        puts 'read_encoded_value_type_int_test failed'
      end
    end


    def read_encoded_value_type_null_test
      value_type, value_arg, data, offset = Utilities::EncodedValue.read_encoded_value("1e")
      if(value_type == 30 && value_arg == 0 && data == nil && offset == 1)
        return true
      else
        return false
      end
    end

    def read_encoded_value_type_int_test
      value_type, value_arg, data, offset = Utilities::EncodedValue.read_encoded_value("0400")
      if(value_type == 4 && value_arg == 0 && data == 0 && offset == 2)
        return true
      else
        return false
      end
    end

    def read_encoded_value_type_method_test
      value_type, value_arg, data, offset = Utilities::EncodedValue.read_encoded_value("1a17")
      if(value_type == 26 && value_arg == 0 && data == 23 && offset == 2)
        return true
      else
        return false
      end
    end
  end
end

Apkfuscator::Tests.new
