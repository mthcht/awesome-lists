rule Trojan_MSIL_Jortklaz_A_2147730699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jortklaz.A"
        threat_id = "2147730699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jortklaz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "C:\\Users\\t-roklaz\\Documents\\Visual Studio 2015\\Projects\\Tests\\Troj\\obj\\Release\\Troj.pdb" ascii //weight: 20
        $x_10_2 = "Troj.exe" ascii //weight: 10
        $x_10_3 = "Wrote to RuntimeBroker.exe memory" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

