rule VirTool_Win32_BopToolz_B_2147844666_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BopToolz.B!MTB"
        threat_id = "2147844666"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BopToolz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 6a 04 68 10 ?? ?? ?? 6a 04 6a 00 68 40 ?? ?? ?? ff 75 f8 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 19 00 02 00 6a 0c 68 a0 ?? ?? ?? ff 75 f4 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 04 68 10 ?? ?? ?? 6a 04 6a 00 68 40 ?? ?? ?? ff 75 f8 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c4 08 a3 10 ?? ?? ?? 8d 45 ?? 50 68 02 00 00 80 ff 35 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

