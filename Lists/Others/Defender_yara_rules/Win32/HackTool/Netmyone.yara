rule HackTool_Win32_Netmyone_B_2147808392_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Netmyone.B!dha"
        threat_id = "2147808392"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Netmyone"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 20 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f ?? 2f 00 64 00 6f 00 63 00 73 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 6e 00 65 00 74 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 2f 00 [0-48] 20 00 [0-48] 20 00 2f 00 75 00 3a 00 [0-48] 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

