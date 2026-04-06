require 'action_dispatch'

class ResponseHandler
  def self.handle_request(content)
    response = ActionDispatch::Response.new(200, {}, [content])
    response.body
  end
end
