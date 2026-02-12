rule HackTool_MSIL_Spoofer_AMTB_2147962930_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Spoofer!AMTB"
        threat_id = "2147962930"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spoofer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DISK successfully spoofed." ascii //weight: 2
        $x_2_2 = "MAC address successfully spoofed." ascii //weight: 2
        $x_2_3 = "Product ID successfully spoofed." ascii //weight: 2
        $x_2_4 = "Machine GUID successfully spoofed." ascii //weight: 2
        $x_2_5 = "HwProfile successfully spoofed." ascii //weight: 2
        $x_1_6 = "SecHex-GUI" ascii //weight: 1
        $n_100_7 = "Uninst.exe" ascii //weight: -100
        $n_100_8 = "Uninstaller.exe" ascii //weight: -100
        $n_100_9 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

