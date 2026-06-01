rule Trojan_Win64_Koceg_GVM_2147970661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Koceg.GVM!MTB"
        threat_id = "2147970661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Koceg"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 01 58 85 c0 74 22 ff 35 f8 61 42 00 e8 89 cf ff ff 59 85 c0 74 08 6a 00 ff 15 1c 60 42 00 6a 32 ff 15 58 60 42 00 eb d7}  //weight: 1, accuracy: High
        $x_2_2 = {8b 85 f0 fe ff ff 40 89 85 f0 fe ff ff a1 14 61 42 00 8b 8d f0 fe ff ff 3b 08 7d 33 a1 10 61 42 00 8b 00 8b 8d f0 fe ff ff ff 34 88 8d 85 f4 fe ff ff 50 e8 d6 04 00 00 59 59 68 28 7f 42 00 8d 85 f4 fe ff ff 50 e8 c3 04 00 00 59 59 eb b1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

