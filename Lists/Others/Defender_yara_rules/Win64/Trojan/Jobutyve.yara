rule Trojan_Win64_Jobutyve_BF_2147837035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Jobutyve.BF!MTB"
        threat_id = "2147837035"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Jobutyve"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 3c 89 c1 83 e1 6c 81 c9 83 00 00 00 25 93 00 00 00 31 c8 34 fb 48 8b 4c 24 50 88 01 8b 44 24 34 ff c0 89 44 24 64 8b 05 [0-4] 8d 48 ff 0f af c8 f6 c1 01 b8 fb b6 06 e1 b9 99 6f fa 91 0f 44 c1 83 3d [0-4] 0a 0f 4c c1 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

