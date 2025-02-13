rule Backdoor_Win32_Mokspolx_A_2147644686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mokspolx.A"
        threat_id = "2147644686"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokspolx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 be 7f 00 00 00 f7 fe 03 00 83 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d6 52 8d 84 35 ?? ?? fe ff 50 53 ff d7 03 f0 05 00 (b8|ba) 00 c8 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ff 10 7d 29 0f b6 ?? 1f 51 68 ?? ?? ?? ?? ba 21 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 84 24 9c 00 00 00 58 5a 4b 00 33 c9 8d 70 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

