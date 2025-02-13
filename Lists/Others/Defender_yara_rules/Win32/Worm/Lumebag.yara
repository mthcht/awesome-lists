rule Worm_Win32_Lumebag_A_2147602684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Lumebag.gen!A"
        threat_id = "2147602684"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Lumebag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 45 f0 50 68 90 d0 03 00 e8 ?? ?? ?? ff 05 a0 86 01 00 50}  //weight: 3, accuracy: Low
        $x_3_2 = {c7 45 e2 50 4b 03 04 66 c7 45 e6 0a 00 ff 75 14 8d 45 ee 50 8d 45 ec 50 e8}  //weight: 3, accuracy: High
        $x_3_3 = {ff 73 04 8f 07 57 8f 43 04 83 c7 04 c7 07 50 4b 01 02 66 c7 47 04 14 00 66 c7 47 06 0a 00}  //weight: 3, accuracy: High
        $x_3_4 = {ff 75 10 6a 03 e8 ?? ?? ?? ff 05 d4 07 00 00 66 01 45 f0 ff 75 10 6a 0a}  //weight: 3, accuracy: Low
        $x_2_5 = {c7 45 d0 00 00 00 00 8b 5d 10 6a 02 6a 00 6a 00 ff 33 e8 ?? ?? ?? 00 83 f8 ff 75 ?? e9}  //weight: 2, accuracy: Low
        $x_2_6 = {f3 a4 8b f8 80 3f d4 75 ?? ff 77 01 8f 45 f0 ff 4d f0 c7 45 f4 56 c3 00 00 ff 75 f4 6a 00 e8 ?? ?? ?? ff 83 6d f4 06}  //weight: 2, accuracy: Low
        $x_1_7 = {8b 75 0c b8 05 84 08 08 33 d2 f7 26 40 89 06 f7 65 08}  //weight: 1, accuracy: High
        $x_1_8 = "Software\\MuleAppData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

