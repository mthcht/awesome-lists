rule HackTool_Win32_DesktopImgDownldr_2147798387_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/DesktopImgDownldr"
        threat_id = "2147798387"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "DesktopImgDownldr"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 2f 00 6c 00 6f 00 63 00 6b 00 73 00 63 00 72 00 65 00 65 00 6e 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /eventName:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

