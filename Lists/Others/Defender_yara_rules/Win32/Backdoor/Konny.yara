rule Backdoor_Win32_Konny_A_2147721349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Konny.A!dha"
        threat_id = "2147721349"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Konny"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 25 73 5c 73 6f 6c 68 65 6c 70 2e 6f 63 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 69 64 3d 25 73 26 70 61 73 73 77 64 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

