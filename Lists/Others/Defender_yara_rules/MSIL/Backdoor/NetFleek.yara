rule Backdoor_MSIL_NetFleek_A_2147947057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NetFleek.A!dha"
        threat_id = "2147947057"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetFleek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoadPlugins" ascii //weight: 1
        $x_1_2 = "GetPlugins" ascii //weight: 1
        $x_1_3 = "ExecutePlugins" ascii //weight: 1
        $x_1_4 = "updLocation" ascii //weight: 1
        $x_1_5 = ".usb" wide //weight: 1
        $x_1_6 = ".scrn" wide //weight: 1
        $x_1_7 = ".soc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NetFleek_B_2147947058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NetFleek.B!dha"
        threat_id = "2147947058"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetFleek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FirmachAgent" ascii //weight: 1
        $x_1_2 = "task/upload" wide //weight: 1
        $x_1_3 = "task/download" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NetFleek_C_2147947059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NetFleek.C!dha"
        threat_id = "2147947059"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetFleek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "robocopy.exe" wide //weight: 1
        $x_1_2 = "/mir /r:1 /w:1 /np /xj /sl" wide //weight: 1
        $x_1_3 = "*.step *.slddrw *.sldprt *.sldasm *.stp *.x_t" wide //weight: 1
        $x_1_4 = "/R:3 /W:5 /XO" wide //weight: 1
        $x_1_5 = "TempEmptyDirectory-" wide //weight: 1
        $x_1_6 = "\\.fs\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

