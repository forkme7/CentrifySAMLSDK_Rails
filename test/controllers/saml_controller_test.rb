require 'test_helper'

class SamlControllerTest < ActionController::TestCase
  test "should get acs" do
    get :acs
    assert_response :success
  end

  test "should get default" do
    get :default
    assert_response :success
  end

end
