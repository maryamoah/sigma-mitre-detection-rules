# Sigma to Wazuh

Wazuh rules use decoder-derived fields, rule chaining, and XML syntax. Translate the detection behavior manually, identify the exact Wazuh decoder fields, test with `wazuh-logtest`, and use a unique local rule ID. A syntactic conversion without field validation is unsafe.
