require_relative 'responder'

class App
  def run
    Responder.build_response("Hello")
  end
end
