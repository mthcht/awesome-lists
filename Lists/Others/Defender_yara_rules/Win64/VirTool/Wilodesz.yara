rule VirTool_Win64_Wilodesz_A_2147847061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Wilodesz.A!MTB"
        threat_id = "2147847061"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Wilodesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 04 01 00 00 ff 15 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8d 8c ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 45 33 c0 48 8d 94 ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 00 00 40 8b f0 ff 15 ?? ?? ?? ?? 48 8b d8 48 83 f8 ff 75}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b cb ff 15 ?? ?? ?? ?? 48 8b 0d e9 35 00 00 48 8d 15 ?? ?? ?? ?? e8 c5 ?? ?? ?? 48 8b c8 48 8d 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

