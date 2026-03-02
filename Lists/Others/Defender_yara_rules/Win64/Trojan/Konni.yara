rule Trojan_Win64_Konni_P_2147963988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Konni.P!MTB"
        threat_id = "2147963988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Konni"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 73 64 65 6c 25 6c 75 2e 62 61 74 00 00 00 00 3a 52 65 70 65 61 74 0d 0a 74 69 6d 65 6f 75 74 20 2f 54 20 32 20 2f 4e 6f 62 72 65 61 6b 20 3e 6e 75 6c 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 25 7e 66 30 22 0d 0a 00 6f 70 65 6e 00 00 00 00 63 6d 64 2e 65 78 65 00 2f 43 20 22 25 73 22 00}  //weight: 10, accuracy: High
        $x_10_2 = {2f 00 63 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 20 00 77 00 69 00 6e 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 20 00 22 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-50] 2f 00 61 00 63 00 63 00 65 00 73 00 73 00 2f 00 52 00 65 00 6d 00 6f 00 74 00 65 00 25 00 32 00 30 00 41 00 63 00 63 00 65 00 73 00 73 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 36 00 34 00 2d 00 6f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

