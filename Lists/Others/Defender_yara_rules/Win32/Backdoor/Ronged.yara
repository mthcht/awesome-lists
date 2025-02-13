rule Backdoor_Win32_Ronged_A_2147678297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ronged.gen!A"
        threat_id = "2147678297"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ronged"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 1d 50 0f b6 44 24 20 51 52 50 8d 0c 2b 68 ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 83 c4 20}  //weight: 1, accuracy: Low
        $x_1_2 = "oth_domain   %s" ascii //weight: 1
        $x_1_3 = "OS Type:     Workstation" ascii //weight: 1
        $x_1_4 = "HOST INFORMATION FOR \\\\%s" ascii //weight: 1
        $x_1_5 = {51 41 5a 32 77 73 78 33 65 64 63 00 00 00 00 53 41 4c 54 5c 77 65 62 75 73 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

