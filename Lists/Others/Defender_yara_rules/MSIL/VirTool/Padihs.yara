rule VirTool_MSIL_Padihs_A_2147711058_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Padihs.A"
        threat_id = "2147711058"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Padihs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 64 00 68 00 74 00 67 00 72 00 2e 00 65 00 78 00 65 00 [0-16] 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 [0-16] 57 00 69 00 6e 00 48 00 74 00 74 00 70 00 41 00 75 00 74 00 6f 00 50 00 72 00 6f 00 78 00 79 00 53 00 79 00 6e 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00 20 00 48 00 6f 00 73 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 [0-16] 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 [0-16] 34 00 2e 00 35 00 31 00 2e 00 31 00 2e 00 31 00 [0-16] 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 [0-16] 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00 20 00 48 00 6f 00 73 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Padihs_B_2147711195_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Padihs.B"
        threat_id = "2147711195"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Padihs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinHTTP Web Proxy Auto-Discovery" wide //weight: 1
        $x_1_2 = {64 69 61 67 68 6f 73 2e 64 6c 6c 00 64 69 61 67 68 6f 73 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
        $x_1_3 = "sandboxierpcss" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

