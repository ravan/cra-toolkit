require 'json'

class JsonParser
  def parse(content)
    JSON.parse(content)
  end
end

def main
  parser = JsonParser.new
  puts parser.parse('{"title": "Hello"}')
end

main
