rule Backdoor_Win32_DCRat_GJK_2147847867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DCRat.GJK!MTB"
        threat_id = "2147847867"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 5d e8 8a 44 1d 10 88 44 3d 10 88 4c 1d 10 0f b6 44 3d 10 03 c2 0f b6 c0 8a 44 05 10 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 83 4d fc ff eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

