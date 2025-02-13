rule Trojan_Linux_E2E_CmdLineTest_2147763868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/E2E_CmdLineTest"
        threat_id = "2147763868"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "E2E_CmdLineTest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "linux_malware" wide //weight: 1
        $x_10_2 = "aad601f7-d76d-4ddc-ab1e-37ab4c3e7e6f" wide //weight: 10
        $x_8_3 = "abc9dc4b-0dfa-42f3-bbc1-dff8de960977" wide //weight: 8
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

