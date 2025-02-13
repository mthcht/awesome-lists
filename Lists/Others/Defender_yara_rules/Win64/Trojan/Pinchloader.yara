rule Trojan_Win64_Pinchloader_A_2147891457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pinchloader.A!dha"
        threat_id = "2147891457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pinchloader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 3d 30 cf 38 00 74 ?? f3 0f 6f 4c 06 f0 f3 0f 6f 14 06 66 0f ef c8 66 0f ef d0 f3 0f 7f 4c 06 f0 f3 0f 7f 14 06 48 83 c0 40}  //weight: 1, accuracy: Low
        $x_1_2 = {22 e1 0e 76 4a 22 e1 26 76 52 05 07 19 08 22 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Pinchloader_B_2147891458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pinchloader.B!dha"
        threat_id = "2147891458"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pinchloader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to allocate memory for shellcode" ascii //weight: 1
        $x_1_2 = "Failed to change memory protection" ascii //weight: 1
        $x_1_3 = {2e 64 6c 6c 00 6f 6b 67 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

