rule HackTool_Win32_NamedPipeImpers_A_2147735445_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NamedPipeImpers.A"
        threat_id = "2147735445"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NamedPipeImpers"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 65 00 63 00 68 00 6f 00 20 00 2f 10 10 00 20 00 3e 00 20 00 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 2f 10 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_NamedPipeImpers_A_2147735445_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NamedPipeImpers.A"
        threat_id = "2147735445"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NamedPipeImpers"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 [0-160] 65 00 63 00 68 00 6f 00 20 00 2f 10 10 00 20 00 3e 00 20 00 5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 2f 10 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

