rule Trojan_Win64_StealthLoader_RDA_2147931058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/StealthLoader.RDA!MTB"
        threat_id = "2147931058"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "StealthLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Global\\3D4AFB1A8CFD43E08524671BEEC8C5EC" ascii //weight: 1
        $x_2_2 = {b9 04 00 00 00 41 8d ?? ?? ?? f3 a4 48 8b cb ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {4d 8b e0 45 8b f9 48 89 58 c8 48 89 58 d0 8b eb 89 58 08 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

