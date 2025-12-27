rule Trojan_MSIL_Marte_PQHH_2147928001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.PQHH!MTB"
        threat_id = "2147928001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DISABLE_FACTORY_RESET" ascii //weight: 3
        $x_2_2 = "reagentc.exe /disable" ascii //weight: 2
        $x_2_3 = "DISABLE_DEFENDER" ascii //weight: 2
        $x_1_4 = "michael-currently.gl.at.ply.gg" ascii //weight: 1
        $x_1_5 = "fodhelper.exe" ascii //weight: 1
        $x_1_6 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marte_AB_2147951421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.AB!MTB"
        threat_id = "2147951421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0b 06 07 16 1a 6f 1d 00 00 0a 26 07 16 28 1c 00 00 0a 0c 06 16 73 cd 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

