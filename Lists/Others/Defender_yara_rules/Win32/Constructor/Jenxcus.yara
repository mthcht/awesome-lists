rule Constructor_Win32_Jenxcus_A_2147691369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Jenxcus.A!cpl"
        threat_id = "2147691369"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jenxcus"
        severity = "Critical"
        info = "cpl: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "njwormcontrolcentre" ascii //weight: 1
        $x_1_2 = "buildnewworm" ascii //weight: 1
        $x_1_3 = "wormservercmdget" ascii //weight: 1
        $x_1_4 = "wormcode" ascii //weight: 1
        $x_3_5 = "www.houdinisc.wix.com/private" ascii //weight: 3
        $x_3_6 = "houdini (c)" ascii //weight: 3
        $x_1_7 = "controler" ascii //weight: 1
        $x_1_8 = "delphi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

