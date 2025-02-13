rule Backdoor_Win32_Khrat_A_2147723989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Khrat.A!dha"
        threat_id = "2147723989"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Khrat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".INTER-CTRIP.COM" ascii //weight: 1
        $x_1_2 = {2e 64 6c 6c 00 4b 31 00 4b 32 00 4b 33}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 0c 8b 75 08 30 06 46 e2 fb 5e 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

