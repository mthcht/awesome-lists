rule Backdoor_Win32_Kanav_B_2147652707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kanav.B"
        threat_id = "2147652707"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kanav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 ec 3b 55 0c 7d 2a e8 ?? ?? ?? ?? 25 0f 00 00 80 79 05 48 83 c8 f0 40 8b 4d 08 03 4d ec 8a 90 ?? ?? ?? ?? 88 11 8b 45 ec 83 c0 01 89 45 ec eb ce}  //weight: 3, accuracy: Low
        $x_3_2 = {6a 02 6a 00 6a da 56 ff 15 ?? ?? ?? ?? 8b 7c 24 14 6a 00 8d 4c 24 0c 51 6a 26 57 56 ff 15 ?? ?? ?? ?? 85 c0 74 41 56 ff 15 ?? ?? ?? ?? 8b c7 8d 50 01 8d a4 24 00 00 00 00 8a 08 40 84 c9 75 f9 2b c2 83 f8 26 74 20 33 d2 89 17 89 57 04}  //weight: 3, accuracy: Low
        $x_3_3 = {25 0f 00 00 80 79 05 48 83 c8 f0 40 8a 80 ?? ?? ?? ?? 88 84 34 38 03 00 00 46 83 fe 05 7c dc 05 00 e8 ?? ?? 00 00}  //weight: 3, accuracy: Low
        $x_1_4 = {2f 75 70 64 61 74 65 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 75 70 67 72 61 64 65 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Active Setup\\Installed Components\\" ascii //weight: 1
        $x_1_7 = "http://dontkillme/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

