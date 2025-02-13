rule PWS_Win32_Mmosteal_2147572805_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Mmosteal"
        threat_id = "2147572805"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Mmosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 6f 6f 6b 44 6c 6c 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00}  //weight: 5, accuracy: High
        $x_5_2 = {53 74 61 72 74 48 6f 6f 6b 00 53 74 6f 70 48 6f 6f 6b}  //weight: 5, accuracy: High
        $x_5_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks" ascii //weight: 5
        $x_5_4 = "URLDownloadToFileA" ascii //weight: 5
        $x_1_5 = "{59502416-6436-4CE9-BC06-3C1156FC3542}" ascii //weight: 1
        $x_1_6 = "{5EED7056-B89D-4DE8-A060-D285EA746799}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

