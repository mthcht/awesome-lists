rule Virus_Win32_Dundun_A_2147602334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Dundun.gen!A"
        threat_id = "2147602334"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Dundun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d b5 33 c0 33 c9 49 f2 ae 81 7f fb 2e 45 58 45 74 0d 81 7f fb 2e 65 78 65 0f 85 34 02 00 00 68 80 00 00 00 ff 74 24 34 ff 55 64 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {8b f9 51 50 33 c0 6a 14 59 fc f3 ab 58 59 c7 01 44 45 4e 47 c7 41 04 20 44 55 4e ff 75 04 8f 41 08}  //weight: 1, accuracy: High
        $x_1_3 = {f3 a4 83 c6 6c 6a 70 59 f3 a4 8b 85 e0 00 00 00 66 8b d8 c1 e8 10 5e 03 75 bd b9 ?? ?? 00 00 30 1e 30 3e 30 06 30 26 46 e2 f5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

