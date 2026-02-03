rule Trojan_Win64_Aotera_KK_2147962258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aotera.KK!MTB"
        threat_id = "2147962258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aotera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b d1 41 8b 54 96 10 43 89 54 8e 10 8b d1 45 89 5c 96 10 41 ff c1 41 81 f9 00 01 00 00}  //weight: 20, accuracy: High
        $x_10_2 = {41 8b c3 41 0f b6 44 86 10 33 d0 41 8b c1 88 54 01 10 41 ff c1 41 3b f9}  //weight: 10, accuracy: High
        $x_5_3 = {41 c1 e7 04 41 0b c7 42 88 44 37 10 83 c5 02 41 ff c6 3b ee 7c c0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

