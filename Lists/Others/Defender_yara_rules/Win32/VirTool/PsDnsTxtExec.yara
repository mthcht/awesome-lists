rule VirTool_Win32_PsDnsTxtExec_B_2147893585_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PsDnsTxtExec.B!MTB"
        threat_id = "2147893585"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDnsTxtExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-16] 28 00 6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 [0-8] 20 00 2d 00 71 00 3d 00 74 00 78 00 74 00 20 00 [0-64] 29 00 5b 00 2d 00 31 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

