rule Virus_Win32_Seppuku_A_2147601574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Seppuku.gen!A"
        threat_id = "2147601574"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Seppuku"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ee 05 ad 0d 20 20 20 20 3d 2e 65 78 65 74 [0-16] 3d 2e 73 63 72}  //weight: 1, accuracy: Low
        $x_1_2 = {66 81 38 4d 5a 0f 85 ?? ?? ?? ?? 66 83 78 08 04 0f 85 ?? ?? ?? ?? 66 81 78 38 52 42 0f 84 ?? ?? ?? ?? 8b 70 3c 03 f0 66 81 3e 50 45 0f 85 ?? ?? ?? ?? ff 76 3c ff b5 ?? ?? ?? ?? ff 95 ?? ?? ?? ?? ff b5 ?? ?? ?? ?? ff 95 ?? ?? ?? ?? 59 8b 85 ?? ?? ?? ?? 05 ?? ?? 00 00 e8 ?? ?? ?? ?? 91 e8 ?? ?? ?? ?? 0b c0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 46 10 89 46 08 5a 8b 46 10 03 46 0c 89 47 50 81 4e 24 20 00 00 a0 8b 85 ?? ?? ?? ?? 66 c7 40 38 52 42 8d b5 ?? ?? ?? ?? 87 fa 8b df 03 9d ?? ?? ?? ?? 8b fb b9 ?? ?? 00 00 f3 a4 c7 85 ?? ?? ?? ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 35 20 83 66 81 f3 b8 ed fe ce 75 ?? 33 c8 33 d3 4f 75 ?? f7 d2 f7 d1 8b c2 c1 c0 10 66 8b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

