rule HackTool_PowerShell_ExchangeMgmRoleAssignment_2147808394_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:PowerShell/ExchangeMgmRoleAssignment.gen"
        threat_id = "2147808394"
        type = "HackTool"
        platform = "PowerShell: "
        family = "ExchangeMgmRoleAssignment"
        severity = "High"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-2] 59 00 51 00 42 00 6b 00 41 00 47 00 51 00 41 00 4c 00 51 00 42 00 77 00 41 00 48 00 4d 00 41 00 63 00 77 00 42 00 75 00 41 00 47 00 45 00 41 00 63 00 41 00 42 00 70 00 41 00 47 00 34 00 41 00 49 00 41 00 41 00 71 00 41 00 47 00 55 00 41 00 65 00 41 00 42 00 6a 00 41 00 47 00 67 00 41 00 59 00 51 00 42 00 75 00 41 00 47 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 5a 00 51 00 41 00 71 00 41 00 44 00 73 00 41 00 49 00 41 00 42 00 4f 00 41 00 47 00 55 00 41 00 64 00 77 00 41 00 74 00 41 00 45 00 30 00 ?? 59 00 51 00 42 00 75 00 41 00 47 00 45 00 41 00 5a 00 77 00 42 00 6c 00 41 00 47 00 30 00 41 00 5a 00 51 00 42 00 75 00 41 00 48 00 51 00 41 00 55 00 67 00 42 00 76 00 41 00 47 00 77 00 41 00 5a 00 51 00 42 00 42 00 41 00 48 00 4d 00 41 00 63 00 77 00 42 00 70 00 41 00 47 00 63 00 41 00 62 00 67 00 42 00 74 00 41 00 47 00 55 00 41 00 62 00 67 00 42 00 30 00 41 00 43 00 41 00 41 00 4c 00 51 00 42 00 75 00 41 00 47 00 45 00 41 00 62 00 51 00 42 00 6c 00 41 00 44 00 6f 00 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

