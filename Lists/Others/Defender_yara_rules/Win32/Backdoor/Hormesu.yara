rule Backdoor_Win32_Hormesu_A_2147654183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hormesu.gen!A"
        threat_id = "2147654183"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormesu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b fb 7e 1b 89 5d fc ff 95 e0 fd ff ff eb 09 b8 01 00 00 00 c3}  //weight: 1, accuracy: High
        $x_1_2 = {55 43 43 6f 64 65 50 69 65 63 65 43 61 6c 6c 65 72 2e 64 6c 6c 00 75 63 67 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Hormesu_B_2147654184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hormesu.gen!B"
        threat_id = "2147654184"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormesu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d f4 03 7d f8 8a 07 c0 c8 03 34 29 88 07 41 3b ce 89 4d f8 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {44 6c 6c 4c 6f 61 64 65 72 2e 64 6c 6c 00 4c 6f 61 64 54 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

