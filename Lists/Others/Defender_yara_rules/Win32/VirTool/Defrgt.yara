rule VirTool_Win32_Defrgt_B_2147956702_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Defrgt.B"
        threat_id = "2147956702"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Defrgt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 ff 75 e8 0f 47 45 08 50 57 56 ff}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 18 68 00 80 00 00 6a 00 57 56 ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

