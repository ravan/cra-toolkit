require_relative 'handlers'

class App
  def run
    result = ResponseHandler.handle_request("Hello")
    puts result
  end
end
