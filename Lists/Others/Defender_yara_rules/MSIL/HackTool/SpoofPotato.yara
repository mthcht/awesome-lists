rule HackTool_MSIL_SpoofPotato_A_2147959269_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/SpoofPotato.A!AMTB"
        threat_id = "2147959269"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpoofPotato"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spoofed target" ascii //weight: 1
        $x_1_2 = "Potato.pdb" ascii //weight: 1
        $x_1_3 = "Potato.exe" ascii //weight: 1
        $x_1_4 = "Starting NBNS spoofer" ascii //weight: 1
        $x_1_5 = "Spoofing wpad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

