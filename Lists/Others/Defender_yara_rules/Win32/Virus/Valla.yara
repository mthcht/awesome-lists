rule Virus_Win32_Valla_A_2147707180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Valla.gen!A"
        threat_id = "2147707180"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Valla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3b 58 4f 52 00 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 03 58 4f 52 00 c7 43 04 00 00 00 00 c7 43 08 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_3 = {80 3e 2e 0f 85 2a 00 00 00 80 7e 01 65 74 06 80 7e 01 45 75 1e 80 7e 02 78 74 06 80 7e 02 58 75 12 80 7e 03 65 74 06 80 7e 03 45 75 06 80 7e 04 00 74 08 80 3e 00 74 33 46 eb c5}  //weight: 2, accuracy: High
        $x_1_4 = {fc e8 00 00 00 00 5f 81 ef ?? 00 00 00 8b 87 ?? ?? 00 00 89 87 ?? ?? 00 00 8b 74 24 1c 81 e6 00 f0 ff ff 66 81 3e 4d 5a}  //weight: 1, accuracy: Low
        $x_1_5 = "-= XOR 2009 Valhalla =-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

