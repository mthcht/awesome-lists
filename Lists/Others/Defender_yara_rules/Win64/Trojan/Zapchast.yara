rule Trojan_Win64_Zapchast_LM_2147962365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zapchast.LM!MTB"
        threat_id = "2147962365"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 0e 48 ff c7 32 44 2f ff 88 44 0f ff}  //weight: 20, accuracy: High
        $x_10_2 = {8b cf c1 e9 05 03 4d 0c 8b c7 c1 e0 04 03 45 08 33 c8 41 8d 04 3c 33 c8 2b f1 8b 84 24 88 00 00 00 44 89 b4 24 88 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

