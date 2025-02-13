rule Backdoor_Win32_GetShell_A_2147658603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GetShell.A"
        threat_id = "2147658603"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GetShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 33 32 00 00 68 77 73 32 5f 54 68 4c 77 26 07 ff d5 b8 90 01 00 00 29 c4 54 50 68 29 80 6b 00 ff d5}  //weight: 1, accuracy: High
        $x_1_2 = {68 58 a4 53 e5 [0-2] [0-2] ff d5}  //weight: 1, accuracy: Low
        $x_1_3 = {97 6a 05 68 ba 57 45 f9 68 02 00 1f 92 89 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

