require 'action_dispatch'

class App
  def run
    response = ActionDispatch::Response.new(200, {}, ["Hello"])
    puts response.body
  end
end

App.new.run
