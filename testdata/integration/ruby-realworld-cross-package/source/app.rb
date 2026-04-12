require 'nokogiri'

class HtmlParser
  def parse(content)
    doc = Nokogiri::HTML(content)
    doc.css('title').text
  end
end

def main
  parser = HtmlParser.new
  puts parser.parse("<html><title>Hello</title></html>")
end

main
