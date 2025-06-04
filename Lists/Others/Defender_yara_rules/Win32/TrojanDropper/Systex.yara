rule TrojanDropper_Win32_Systex_AST_2147942814_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Systex.AST!MTB"
        threat_id = "2147942814"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Systex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 3f 00 0f 00 53 53 ff 15 ?? ?? ?? ?? 6a 02 8b f0 68 70 bb 40 00 56 ff 15 ?? ?? ?? ?? 53 53 53 53 53 53 53 6a ff 6a 03 8b f8 6a ff 57}  //weight: 3, accuracy: Low
        $x_2_2 = {83 c4 04 e8 ?? ?? ?? ?? 99 b9 1a 00 00 00 f7 f9 6a 14 8b da ff d7 80 c3 61 6a 1e 88 9c 34 c8 00 00 00 ff d7 46}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

