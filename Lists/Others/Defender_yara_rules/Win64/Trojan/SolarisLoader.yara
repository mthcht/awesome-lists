rule Trojan_Win64_SolarisLoader_ASL_2147972958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SolarisLoader.ASL!MTB"
        threat_id = "2147972958"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SolarisLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 85 c0 75 0e 48 8b cf ff 15 ?? ?? ?? ?? 48 85 c0 74 6a 48 8b d6 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 74 56 ba 08 00 00 00 4c 8d 4c 24 30 48 8b c8 44 8d 42 38}  //weight: 1, accuracy: Low
        $x_2_2 = {66 c7 44 24 3c 80 c3 41 8d 50 06 49 63 c8 41 ff c0 8a 44 0c 38 88 04 19 44 3b c2 72 ee 44 8b 44 24 30 4c 8d 4c 24 30 48 8b cb ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

