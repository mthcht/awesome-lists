rule VirTool_Win32_Toksteal_A_2147622711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Toksteal.A"
        threat_id = "2147622711"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Toksteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f8 8b 0d ?? ?? ?? ?? 89 4d f4}  //weight: 2, accuracy: Low
        $x_5_2 = {8b f4 6a 00 6a 03 8d 55 f8 52 a1 ?? ?? ?? ?? 50 8b 4d 08 51 ff 15 ?? ?? ?? ?? 3b f4 e8 ?? ?? ?? ?? 8b f4 8d 55 fc 52 8b 45 fc 50 6a 03}  //weight: 5, accuracy: Low
        $x_1_3 = "Win32_Process" wide //weight: 1
        $x_1_4 = "root\\cimv2  " wide //weight: 1
        $x_1_5 = "wmiprvse.exe" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "DuplicateHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_Toksteal_B_2147622712_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Toksteal.B"
        threat_id = "2147622712"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Toksteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 52 6a 00 ff 15 ?? ?? ?? ?? 8d 45 b4 50 6a 00 68 ff 01 0f 00 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? eb 06 8b 4d 08 89 4d b4 8d 55 fc 52 6a 01 6a 02 6a 00 68 00 00 00 02 8b 45 b4 50 ff 15}  //weight: 10, accuracy: Low
        $x_2_2 = "-->Found SYSTEM token 0x%x" ascii //weight: 2
        $x_2_3 = "-->Found %s Token" ascii //weight: 2
        $x_2_4 = "DuplicateToken" ascii //weight: 2
        $x_2_5 = "DtcGetTransactionManagerExA" ascii //weight: 2
        $x_2_6 = {4e 45 54 57 4f 52 4b 20 53 45 52 56 49 43 45 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

