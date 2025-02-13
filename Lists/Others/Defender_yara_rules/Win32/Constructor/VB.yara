rule Constructor_Win32_VB_K_2147641189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/VB.K"
        threat_id = "2147641189"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "clsFileBinder" ascii //weight: 2
        $x_2_2 = "txtEXE1" ascii //weight: 2
        $x_4_3 = "\\EXE Joiner.vbp" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

