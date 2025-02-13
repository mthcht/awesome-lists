rule Backdoor_Win32_Garex_A_2147693309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Garex.A!dha"
        threat_id = "2147693309"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Garex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {50 53 53 53 c6 45 e8 42 c6 45 e9 6b c6 45 ea 61 c6 45 eb 76 c6 45 ec 46 c6 45 ed 69 c6 45 ee 72 c6 45 ef 65 c6 45 f0 77 c6 45 f1 61 c6 45 f2 6c c6 45 f3 6c c6 45 f4 53 c6 45 f5 65 c6 45 f6 72 c6 45 f7 76 c6 45 f8 65 c6 45 f9 72 88 5d fa ff d6 3b c3}  //weight: 4, accuracy: High
        $x_4_2 = {8b 13 8b ca 8b f2 c1 e9 1d c1 ee 1e 8b fa 83 e1 01 83 e6 01 c1 ef 1f f7 c2 00 00 00 02}  //weight: 4, accuracy: High
        $x_2_3 = "PythonThreadStart" ascii //weight: 2
        $x_2_4 = "SOFTWARE\\Microsoft\\Windows Update Reporting" ascii //weight: 2
        $x_2_5 = "{67BDE5D7-C2FC-8898-9096-C255AB791B75}" ascii //weight: 2
        $x_2_6 = "{AC634028-9BF2-4a68-8C93-F515DA893779}" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

