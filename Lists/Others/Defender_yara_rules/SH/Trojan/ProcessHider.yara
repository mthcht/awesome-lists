rule Trojan_SH_ProcessHider_SR6_2147950259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:SH/ProcessHider.SR6"
        threat_id = "2147950259"
        type = "Trojan"
        platform = "SH: Shell scripts"
        family = "ProcessHider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {65 00 63 00 68 00 6f 00 20 00 22 00 2f 00 75 00 73 00 72 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 6c 00 69 00 62 00 2f 00 6c 00 69 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 69 00 64 00 65 00 72 00 2e 00 73 00 6f 00 22 00 20 00 3e 00 [0-2] 2f 00 65 00 74 00 63 00 2f 00 6c 00 64 00 2e 00 73 00 6f 00 2e 00 70 00 72 00 65 00 6c 00 6f 00 61 00 64 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

