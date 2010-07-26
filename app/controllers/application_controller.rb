require_dependency 'authenticated_system'

class ApplicationController < ActionController::Base
  include AuthenticatedSystem
  protect_from_forgery
end
