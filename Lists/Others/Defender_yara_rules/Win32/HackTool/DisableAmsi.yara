rule HackTool_Win32_DisableAmsi_2147731144_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DisableAmsi"
        threat_id = "2147731144"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DisableAmsi"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 55 73 65 72 73 5c 61 6e 64 72 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 42 79 70 61 73 73 41 4d 53 49 5c 42 79 70 61 73 73 41 4d 53 49 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 41 4d 53 49 2e 70 64 62 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_DisableAmsi_A_2147731145_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DisableAmsi.A"
        threat_id = "2147731145"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DisableAmsi"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 53 44 53 [0-24] 43 3a 5c 44 65 76 65 6c 6f 70 6d 65 6e 74 5c 41 6d 73 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 6d 73 69 2e 70 64 62 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

