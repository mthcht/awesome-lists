rule Backdoor_Win32_Darkshell_A_2147642860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Darkshell.A"
        threat_id = "2147642860"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Darkshell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4b e1 22 00 0f 85 ?? ?? 00 00 83 65 ?? 00 6a 04 6a 04}  //weight: 1, accuracy: Low
        $x_1_2 = {83 4d fc ff 8b 1b [0-3] a1 ?? ?? ?? ?? 39 58 ?? 77 ?? c7 45 ?? 0d 00 00 c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

