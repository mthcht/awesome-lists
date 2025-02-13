rule HackTool_Win32_Impacket_A_2147777725_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Impacket.A"
        threat_id = "2147777725"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Impacket"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-hashes " wide //weight: 10
        $x_10_2 = "-just-dc-ntlm" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

