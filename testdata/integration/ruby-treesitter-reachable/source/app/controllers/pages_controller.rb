class PagesController < ApplicationController
  def parse
    html = Nokogiri::HTML(params[:content])
    render json: { title: html.css('title').text }
  end
end
