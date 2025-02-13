rule HackTool_Win32_Kirbikator_2147740618_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Kirbikator"
        threat_id = "2147740618"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Kirbikator"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kirbi|ccache|wce|lsa|kirbis|ccaches|wces" ascii //weight: 1
        $x_1_2 = "kiwi_ccache_read" ascii //weight: 1
        $x_1_3 = "kiwi_wce_read" ascii //weight: 1
        $x_1_4 = "kiwi_ccache_size_header_krbcred" ascii //weight: 1
        $x_1_5 = "kirbikator" ascii //weight: 1
        $x_1_6 = "LsaCallAuthenticationPackage" ascii //weight: 1
        $x_1_7 = "krbcredinfo" ascii //weight: 1
        $x_1_8 = "ticket-info" ascii //weight: 1
        $x_1_9 = "gentilkiwi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

