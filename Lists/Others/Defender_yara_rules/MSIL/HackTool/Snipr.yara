rule HackTool_MSIL_Snipr_AMTB_2147960049_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Snipr!AMTB"
        threat_id = "2147960049"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snipr"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Web-Installer for SNIPR" ascii //weight: 1
        $x_2_2 = "C:\\Users\\PRAGMA\\Documents\\Projects\\SNIPR-Installer\\SNIPR-Installer\\obj\\Release\\SNIPR-Installer.pdb" ascii //weight: 2
        $x_1_3 = "SNIPR.lnk" ascii //weight: 1
        $x_1_4 = "SNIPR.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

