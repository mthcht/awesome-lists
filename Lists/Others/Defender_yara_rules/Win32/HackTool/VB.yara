rule HackTool_Win32_VB_EA_2147597232_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/VB.EA"
        threat_id = "2147597232"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "Detective 2oo3" ascii //weight: 10
        $x_10_3 = "mMsnPacketsTotal" ascii //weight: 10
        $x_10_4 = "Version 2.0 by kaos" ascii //weight: 10
        $x_10_5 = "M S N . D E T E C T I V E" ascii //weight: 10
        $x_1_6 = "http://www.8th-wonder.net" ascii //weight: 1
        $x_1_7 = "http://kaos.8thw.com" ascii //weight: 1
        $x_1_8 = "2c49f800-c2dd-11cf-9ad6-0080c7e7b78d" wide //weight: 1
        $x_1_9 = "9368265E-85FE-11d1-8BE3-0000F8754DA1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

