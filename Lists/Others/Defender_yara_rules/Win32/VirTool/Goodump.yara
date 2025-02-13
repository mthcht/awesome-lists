rule VirTool_Win32_Goodump_2147783673_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Goodump!MTB"
        threat_id = "2147783673"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Goodump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 8d 45 ?? 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Google\\Chrome\\User Data\\Default\\" ascii //weight: 1
        $x_1_3 = {53 45 4c 45 43 54 [0-32] 61 63 74 69 6f 6e 5f 75 72 6c 2c [0-32] 75 73 65 72 6e 61 6d 65 5f 76 61 6c 75 65 2c [0-32] 70 61 73 73 77 6f 72 64 5f 76 61 6c 75 65 [0-32] 46 52 4f 4d [0-32] 6c 6f 67 69 6e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

