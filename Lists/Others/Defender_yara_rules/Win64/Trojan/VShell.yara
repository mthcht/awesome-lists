rule Trojan_Win64_VShell_LVK_2147970046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VShell.LVK!MTB"
        threat_id = "2147970046"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 20 89 54 24 18 29 d6 8d 4e 04 89 cb f7 d9 c1 f9 1f 21 d1 01 e9 89 0c 24 89 5c 24 04 89 5c 24 08 0f b7 cf 89 4c 24 0c e8 6c 91 00 00 8b 44 24 10 8b 4c 24 20 41 8b 54 24 18 01 c2 8b 44 24 30 8b 5c 24 14 8b 6c 24 38 8b 74 24 1c 89 eb 89 c5 89 c8 8b 4c 24 14 3d fe ff ff 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

