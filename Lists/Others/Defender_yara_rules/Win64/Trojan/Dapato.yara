rule Trojan_Win64_Dapato_NA_2147950686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Dapato.NA!MTB"
        threat_id = "2147950686"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Dapato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4c 63 25 8f cd 0f 00 41 8d 4c 24 01 48 63 c9 48 c1 e1 03 e8 56 93 01 00 49 89 c5 48 85 c0 74 57}  //weight: 2, accuracy: High
        $x_1_2 = {e8 73 92 01 00 4c 8b 05 5c cf 0f 00 8b 0d 66 cf 0f 00 4c 89 00 48 8b 15 54 cf 0f 00 e8 f7 ba 0c 00 8b 0d 39 cf 0f 00 85 c9 0f 84 fb 02 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

