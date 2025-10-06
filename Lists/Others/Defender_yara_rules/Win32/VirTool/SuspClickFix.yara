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

