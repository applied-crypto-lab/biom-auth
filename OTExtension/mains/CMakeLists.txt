

add_executable(authentication_test authentication_test.cpp)
target_link_libraries(authentication_test PUBLIC PeerNet PUBLIC justGarble PUBLIC OTExtension::otextension)

add_executable(test_controller test_controller.cpp)
target_link_libraries(test_controller PUBLIC PeerNet PUBLIC OTExtension::otextension)



