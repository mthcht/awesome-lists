rule VirTool_Win32_BilapLdz_B_2147841299_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/BilapLdz.B!MTB"
        threat_id = "2147841299"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "BilapLdz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b 76 04 56 68 5c 21 40 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 85 e0 fd ff ff 00 00 00 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 68 90 01 04 ff}  //weight: 1, accuracy: High
        $x_1_3 = {88 44 35 ec 46 83 fe 10 72 e6}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 8d 85 ?? ?? ?? ?? 50 57 56 53 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

