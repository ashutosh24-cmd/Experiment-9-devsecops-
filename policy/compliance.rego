package compliance

import rego.v1

deny contains "Application name must not be empty" if {
    input.app_name == ""
}

deny contains "Application port must be between 1024 and 65535" if {
    input.port < 1024
}

deny contains "Debug mode must be disabled" if {
    input.debug == true
}

deny contains "Insecure TLS must be disabled" if {
    input.insecure_tls == true
}
deny contains "Application log must be enabled" if {
    input.application_log == false
}
