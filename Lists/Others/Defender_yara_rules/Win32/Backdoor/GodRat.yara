rule Backdoor_Win32_GodRat_CI_2147959306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/GodRat.CI!MTB"
        threat_id = "2147959306"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "GodRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 01 80 c2 41 80 f2 ?? 80 c2 41 80 f2 ?? 80 c2 41 80 f2 ?? 88 14 01 41 3b ce 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

