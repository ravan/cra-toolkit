require 'action_dispatch'

class Responder
  def self.build_response(content)
    response = ActionDispatch::Response.new(200, {}, [content])
    response.body
  end
end
