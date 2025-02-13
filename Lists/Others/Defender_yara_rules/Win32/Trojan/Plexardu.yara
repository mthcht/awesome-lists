rule Trojan_Win32_Plexardu_A_2147661041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plexardu.A"
        threat_id = "2147661041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plexardu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4e 02 84 c9 74 02 30 0a 8a 0a f6 d1 84 c9 88 0a 74 03}  //weight: 1, accuracy: High
        $x_1_2 = {80 78 0c 08 0f 85 ?? ?? ?? ?? 80 78 0d 06 75 ?? 8a 48 14 84 c9 75 ?? 80 78 15 02 75}  //weight: 1, accuracy: Low
        $x_1_3 = {80 fa 7b 75 2b 8a 45 1b 3c 7d 75 0c 8a 4d 1c 80 f9 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

