rule HackTool_Linux_DiscoverCredentials_BZ4_2147966060_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/DiscoverCredentials.BZ4"
        threat_id = "2147966060"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "DiscoverCredentials"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "grep " wide //weight: 10
        $x_10_2 = "pem|key|cred|db|sqlite|conf|cnf|ini|env|secret|token|auth|passwd|shadow" wide //weight: 10
        $x_10_3 = {2f 00 70 00 72 00 6f 00 63 00 2f 00 [0-64] 2f 00 6d 00 61 00 70 00 73 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

