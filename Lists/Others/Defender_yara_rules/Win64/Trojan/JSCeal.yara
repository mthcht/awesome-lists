rule Trojan_Win64_JSCeal_HB_2147948961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/JSCeal.HB!MTB"
        threat_id = "2147948961"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "JSCeal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {73 65 74 50 72 6f 78 79 00 00 00 00 00 00 00 00 6c 69 73 74 50 72 6f 63 65 73 73 65 73 00 00 00 67 65 74 50 72 6f 63 65 73 73 4c 6f 63 61 74 69 6f 6e 00 00 00 00 00 00 67 65 74 50 72 6f 63 65 73 73 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 54 6f 6b 65 6e 00 00 00 00 6b 69 6c 6c 50 72 6f 63 65 73 73 00 00 00 00 00 69 73 43 6f 6e 73 6f 6c 65 4c 6f 63 6b 65 64 00 67 65 74 41 63 74 69 76}  //weight: 20, accuracy: High
        $x_25_2 = {73 65 74 44 50 49 41 77 61 72 65 6e 65 73 73 00 69 6e 69 74 69 61 6c 69 7a 65 44 65 74 6f 75 72 73 00 00 00 00 00 00 00 73 65 74 43 72 65 61 74 65 50 72 6f 63 65 73 73 54 6f 6b 65 6e 00 00 00 73 65 61 72 63 68 50 61 74 68 00 00 00 00 00 00 67 65 74 55 73 65 72 44}  //weight: 25, accuracy: High
        $x_15_3 = {6e 6f 64 65 2e 64 6c 6c 00 00 00 00 6e 77 2e 64 6c 6c 00 00 00 00 00 00 6e 6f 64 65 2e 65 78 65 00 00 00 00 00 00 00 00 6e 6f 64 65 2e 65 78 65 00 00 00 00}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

