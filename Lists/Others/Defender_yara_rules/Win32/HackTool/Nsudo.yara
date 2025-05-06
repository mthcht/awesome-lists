rule HackTool_Win32_Nsudo_B_2147829957_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Nsudo.B"
        threat_id = "2147829957"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nsudo"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "u:t" wide //weight: 1
        $x_1_2 = "u=t" wide //weight: 1
        $x_2_3 = "nsudo" wide //weight: 2
        $n_1000_4 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_5 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

