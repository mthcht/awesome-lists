rule HackTool_Win32_ZorSaw_A_2147894761_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ZorSaw.A!dha"
        threat_id = "2147894761"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ZorSaw"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {05 75 16 83 ?? 01 0f 85 ?? ?? ?? ?? 81 ?? 18 00 01 00 00 0f 85}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

