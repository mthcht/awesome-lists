rule VirTool_Win32_DupDumz_A_2147818942_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/DupDumz.A!MTB"
        threat_id = "2147818942"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DupDumz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 74 6c 41 64 6a 75 73 74 50 72 69 76 69 6c 65 67 65 [0-80] 44 49 6e 76 6f 6b 65 [0-32] 44 79 6e 61 6d 69 63 41 50 49 49 6e 76 6f 6b 65 [0-32] 44 49 6e 76 6f 6b 65 2e 44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65}  //weight: 1, accuracy: Low
        $x_1_2 = {47 65 74 4c 73 61 73 73 48 61 6e 64 6c 65 [0-32] 50 72 6f 63 65 73 73 48 61 6e 64 6c 65 [0-32] 68 46 69 6c 65 [0-32] 47 65 74 41 72 67 75 6d 65 6e 74 73 46 72 6f 6d 46 69 6c 65 [0-32] 69 6e 46 69 6c 65 [0-32] 64 75 6d 70 46 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_4 = "MiniDumpToMemSharp" ascii //weight: 1
        $x_1_5 = {4c 73 61 73 73 [0-80] 68 50 72 6f 63 65 73 73 [0-32] 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

