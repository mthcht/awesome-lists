rule HackTool_Win32_Uflooder_A_2147711062_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Uflooder.A!bit"
        threat_id = "2147711062"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Uflooder"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ICMP Flood" wide //weight: 1
        $x_1_2 = "UDP Flood" wide //weight: 1
        $x_1_3 = "TCP Attack" wide //weight: 1
        $x_1_4 = "TCP Multiple DDoS" wide //weight: 1
        $x_1_5 = "UDP Multiple DDoS" wide //weight: 1
        $x_1_6 = "Random CC Attack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Win32_Uflooder_B_2147711064_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Uflooder.B!bit"
        threat_id = "2147711064"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Uflooder"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYN Flood" wide //weight: 1
        $x_1_2 = "ICMP Flood" wide //weight: 1
        $x_1_3 = "UDP Flood" wide //weight: 1
        $x_1_4 = "TCP Flood" wide //weight: 1
        $x_1_5 = "Established Attack" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

