rule Trojan_MSIL_CloudySky_A_2147757515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CloudySky.A!dha"
        threat_id = "2147757515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CloudySky"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://outlook.office365.com/EWS/Exchange.asmx" wide //weight: 1
        $x_1_2 = "subject:STOC:" wide //weight: 1
        $x_1_3 = "bin.cnt" wide //weight: 1
        $x_1_4 = "Version.exe" ascii //weight: 1
        $x_2_5 = {01 03 06 3f 05 07 03 02 08 41}  //weight: 2, accuracy: High
        $x_1_6 = "000:0:2:5.0.2500.0" ascii //weight: 1
        $x_3_7 = "e2fc1773-26cd-49be-b468-89d1bddb4308" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

