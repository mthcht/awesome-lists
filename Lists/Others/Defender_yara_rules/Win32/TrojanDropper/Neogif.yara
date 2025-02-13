rule TrojanDropper_Win32_Neogif_A_2147688357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Neogif.A"
        threat_id = "2147688357"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Neogif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "m4qtrsz5bfn3o1g" ascii //weight: 2
        $x_2_2 = "/h.gif?pid =113&v=130586214568 HTTP/1.1" ascii //weight: 2
        $x_2_3 = "%skbdmgr.lnk" ascii //weight: 2
        $x_2_4 = "%skbdmgr.exe" ascii //weight: 2
        $x_1_5 = "Serverz.dll" ascii //weight: 1
        $x_1_6 = "210.209.118.87" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

