rule Trojan_Win32_Ligsetrac_A_2147626098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ligsetrac.gen!A"
        threat_id = "2147626098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ligsetrac"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 00 00 00 00 58 05 3c a3 40 00 2d 2d a3 40 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c6 02 e9 8b 48 1c 2b 48 18 83 e9 05 8d 42 01 89 08 c3}  //weight: 1, accuracy: High
        $x_1_3 = {81 38 54 43 53 2c 74 0b 8d 43 04 81 38 48 53 54 2c 75}  //weight: 1, accuracy: High
        $x_1_4 = {6a 06 6a 30 68 02 01 00 00 56 e8 ?? ?? ?? ?? 68 01 00 1c 00 6a 0d 68 00 01 00 00 56 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba 88 13 00 00 e8 ?? ?? ?? ?? 8b f0 85 f6 0f 84}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 08 80 f9 41 72 0b 81 e1 ff 00 00 00 83 e9 11 88 08 42 40 83 fa 04 75 e7}  //weight: 1, accuracy: High
        $x_1_6 = {c7 00 ff ff ff ff 8d 45 ec c7 00 f0 f0 f0 f0 8d 45 f0 c7 00 f0 f0 f0 f0 8d 45 f4 c7 00 f0 f0 f0 f0 8d 45 f8 66 c7 00 f0 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

