rule PWS_Win32_RedLineStealer_GKM_2147775624_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/RedLineStealer.GKM!MTB"
        threat_id = "2147775624"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b f7 c1 e6 04 03 b4 24 ?? ?? ?? ?? 8d 0c 3b 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

