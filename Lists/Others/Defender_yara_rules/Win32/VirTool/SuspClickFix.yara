rule VirTool_Win32_SuspClickFix_M_2147954202_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspClickFix.M"
        threat_id = "2147954202"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "root@finger." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_SuspClickFix_O_2147955818_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspClickFix.O"
        threat_id = "2147955818"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 6d 00 73 00 65 00 64 00 67 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {20 00 2d 00 2d 00 67 00 70 00 75 00 2d 00 6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 3d 00 [0-2] 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2d 00 2d 00 67 00 70 00 75 00 2d 00 6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 3d 00 [0-2] 63 00 6d 00 64 00}  //weight: 1, accuracy: Low
        $x_1_4 = " --disable-gpu-sandbox " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

