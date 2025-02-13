rule Trojan_Win32_Neroblamy_RPX_2147908494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neroblamy.RPX!MTB"
        threat_id = "2147908494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neroblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 7d d4 00 00 58 40 c1 e8 d6 68 51 d7 00 00 58 2d 13 a1 0d 00 c1 f8 52 58}  //weight: 1, accuracy: High
        $x_1_2 = {83 65 80 00 8b 45 f4 89 85 4c ff ff ff 8b 45 f8 89 85 54 ff ff ff 83 7d f4 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

