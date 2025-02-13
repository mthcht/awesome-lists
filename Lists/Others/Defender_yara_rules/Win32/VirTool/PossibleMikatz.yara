rule VirTool_Win32_PossibleMikatz_A_2147849803_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PossibleMikatz.A!cbl4"
        threat_id = "2147849803"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleMikatz"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pr::d" wide //weight: 1
        $x_1_2 = "slsa::htp /user:" wide //weight: 1
        $x_1_3 = " /ntlm:" wide //weight: 1
        $x_1_4 = " /domain:" wide //weight: 1
        $x_1_5 = " /remotepc:" wide //weight: 1
        $x_1_6 = " /pexe:" wide //weight: 1
        $x_1_7 = " /sys:" wide //weight: 1
        $x_1_8 = " /prun:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_PossibleMikatz_B_2147849914_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PossibleMikatz.B!cbl4"
        threat_id = "2147849914"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PossibleMikatz"
        severity = "Critical"
        info = "cbl4: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lsdu::go /ynot " wide //weight: 2
        $x_2_2 = "pr::d slsa::lop " wide //weight: 2
        $x_1_3 = " quit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

