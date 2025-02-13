rule PWS_Win32_Babar_A_2147691874_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Babar.A!dha"
        threat_id = "2147691874"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Babar"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 4d 5a 00 00 33 ff 89 5d d0 c6 45 e8 01 c6 45 e9 02 c6 45 ea 03 c6 45 eb 04 c6 45 ec 05 c6 45 ed 06 c6 45 ee 07 c6 45 ef 08 66 39 03 0f 85 ?? ?? ?? ?? 8b 43 3c 03 c3 81 38 50 45 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7e 14 00 75 ?? 68 31 70 79 66 e8 ?? ?? ?? ?? 89 46 14}  //weight: 1, accuracy: Low
        $x_1_3 = {83 7e 20 00 75 ?? 68 db 07 a2 af e8 ?? ?? ?? ?? 89 46 20}  //weight: 1, accuracy: Low
        $x_1_4 = "8eb762f4;95bb6519;fefd4f5b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

