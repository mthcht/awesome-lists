rule Backdoor_Win32_Taselk_2147602719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Taselk"
        threat_id = "2147602719"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Taselk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2e c7 45 f8 01 00 00 00 8b 45 fc 8b 55 f8 8a 5c 10 ff 80 c3 80 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8b 55 f4 8b c7 e8 ?? ?? ?? ?? ff 45 f8 4e 75 d9}  //weight: 1, accuracy: Low
        $x_1_2 = {66 b8 00 00 66 e7 70 66 89 c3 66 b8 00 00 66 e7 71 66 89 d8 66 40 66 3d 3f 00 75 e8 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

