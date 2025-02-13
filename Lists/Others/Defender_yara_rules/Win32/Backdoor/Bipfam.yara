rule Backdoor_Win32_Bipfam_A_2147642237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bipfam.A"
        threat_id = "2147642237"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bipfam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 eb 03 00 00 68 e9 03 00 00 e8 ?? ?? ?? ?? 83 c4 10 89 45 f0 83 7d f0 ff 75 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 d0 c1 e0 03 01 d0 8d 0c 85 00 00 00 00 8b 16 8b ?? ?? 89 44 0a 18 8d ?? ?? ff 00 eb ?? 8b ?? ?? c7 40 04 32 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

