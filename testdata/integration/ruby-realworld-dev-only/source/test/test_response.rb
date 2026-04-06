require 'action_dispatch'
def test_response_body
  response = ActionDispatch::Response.new(200, {}, ["test"])
  response.body
end
