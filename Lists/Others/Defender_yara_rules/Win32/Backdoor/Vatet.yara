rule Backdoor_Win32_Vatet_SA_2147815176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vatet.SA"
        threat_id = "2147815176"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "cmd" wide //weight: 10
        $x_1_2 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 68 00 65 00 6c 00 70 00 5c 00 [0-16] 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 64 00 65 00 62 00 75 00 67 00 5c 00 [0-16] 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 69 00 6e 00 66 00 5c 00 [0-16] 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6d 00 65 00 64 00 69 00 61 00 5c 00 [0-16] 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Vatet_SLA_2147823746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Vatet.SLA!dha"
        threat_id = "2147823746"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\help\\" wide //weight: 1
        $x_1_2 = "c:\\windows\\debug\\" wide //weight: 1
        $x_1_3 = "c:\\windows\\inf\\" wide //weight: 1
        $x_1_4 = "c:\\windows\\media\\" wide //weight: 1
        $x_1_5 = "googleupdate.exe" wide //weight: 1
        $x_5_6 = "goopdate.dll.dat" wide //weight: 5
        $n_100_7 = "osqueryi.exe" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

