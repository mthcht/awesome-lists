rule Backdoor_Win32_DriWrap_SD_2147765582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DriWrap.SD!MTB"
        threat_id = "2147765582"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DriWrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TAIL:" ascii //weight: 1
        $x_1_2 = "KEY:" ascii //weight: 1
        $x_1_3 = {56 57 8b fa 8b f1 8b cf e8 ?? ?? ?? ?? 85 c0 75 ?? 81 [0-6] 75}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c9 2b d0 8d ?? ?? 33 ?? 0f b7 [0-4] 66 89 [0-4] 66 3b ?? 74 [0-8] 41 3b ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

