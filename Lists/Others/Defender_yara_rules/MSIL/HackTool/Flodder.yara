rule HackTool_MSIL_Flodder_AMTB_2147962641_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Flodder!AMTB"
        threat_id = "2147962641"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flodder"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ChooseAttack" ascii //weight: 1
        $x_1_2 = "SheetExploit.Exploits" ascii //weight: 1
        $x_1_3 = "Spot Flood" ascii //weight: 1
        $x_1_4 = "Enter path for the file. (NOT FOLDER!)" ascii //weight: 1
        $x_1_5 = "Enter hwid for spoofing." ascii //weight: 1
        $x_1_6 = "Tried attempt to send packet with fake user." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

