rule Trojan_Win32_Rolnoxo_A_2147599478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rolnoxo.A"
        threat_id = "2147599478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rolnoxo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 ca 00 00 00 8d bd 64 fd ff ff 4f 8a 47 01 47 3a c3 75 f8 be ?? ?? 40 00 a5 66 a5 33 c0 8d 7d cc ab ab 6a 11 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Rolnoxo_A_2147599479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rolnoxo.A"
        threat_id = "2147599479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rolnoxo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 0a 89 46 06 8d 45 fc 50 c6 06 55 c7 46 01 8b ec eb 05 c6 46 05 e9 ff 75 fc 6a 0a 56 ff d7 89 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

