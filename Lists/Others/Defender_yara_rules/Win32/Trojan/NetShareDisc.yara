rule Trojan_Win32_NetShareDisc_V_2147768645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetShareDisc.V"
        threat_id = "2147768645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetShareDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 67 00 65 00 74 00 2d 00 73 00 6d 00 62 00 73 00 68 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetShareDisc_NS_2147769158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetShareDisc.NS"
        threat_id = "2147769158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetShareDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 20 00 [0-16] 73 00 68 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 73 00 68 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 31 00 20 00 [0-16] 73 00 68 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 [0-16] 73 00 68 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $n_5_5 = "SearchIndex=" wide //weight: -5
        $n_10_6 = {20 00 2f 00 67 00 72 00 61 00 6e 00 74 00 3a 00 [0-128] 2c 00 52 00 45 00 41 00 44 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

