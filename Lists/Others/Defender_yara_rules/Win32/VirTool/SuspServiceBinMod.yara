rule VirTool_Win32_SuspServiceBinMod_A_2147849833_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspServiceBinMod.A!cbl4"
        threat_id = "2147849833"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspServiceBinMod"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = " /t REG_EXPAND_SZ " wide //weight: 1
        $x_1_4 = " /v ImagePath " wide //weight: 1
        $x_1_5 = {20 00 2f 00 64 00 20 00 63 00 6d 00 64 00 [0-8] 20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 6d 00 78 00 73 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

