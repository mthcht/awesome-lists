rule HackTool_Win32_CMConfigUpdate_2147831228_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CMConfigUpdate"
        threat_id = "2147831228"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CMConfigUpdate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 6d 00 70 00 6f 00 72 00 74 00 2d 00 63 00 6d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 20 00 [0-48] 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 [0-32] 69 00 70 00 [0-48] 6d 00 61 00 63 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $n_1000_2 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_3 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

