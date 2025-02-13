rule VirTool_Win32_Shelljec_B_2147841301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shelljec.B!MTB"
        threat_id = "2147841301"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelljec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 ff 15 ?? ?? ?? ?? 56 6a 00 68 ff ff 1f 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 68 00 30 00 00 68 c8 00 00 00 6a 00 56 ff}  //weight: 1, accuracy: High
        $x_1_3 = {6a 00 68 c8 00 00 00 68 90 01 04 57 56 ff}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 00 6a 00 57 6a 00 6a 00 56 ff}  //weight: 1, accuracy: High
        $x_1_5 = {6a ff 53 ff 15 ?? ?? ?? ?? 68 30 23 40 00 51 8b 0d a4 40 40 00 ba 9c 43 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

