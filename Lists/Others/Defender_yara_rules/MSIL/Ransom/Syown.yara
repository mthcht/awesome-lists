rule Ransom_MSIL_Syown_2147725267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Syown"
        threat_id = "2147725267"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Syown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SYSDOWN.exe" ascii //weight: 2
        $x_2_2 = "SYSDOWN.pdb" ascii //weight: 2
        $x_2_3 = "SYSDOWN.My.Resources" ascii //weight: 2
        $x_2_4 = "SYSDOWN.Form1.resources" ascii //weight: 2
        $x_2_5 = "SYSDOWN.Resources.resources" ascii //weight: 2
        $x_2_6 = "SYSDOWN.g.resources" ascii //weight: 2
        $x_2_7 = "5d19299a-7d9e-43de-956a-70997875cfaa" ascii //weight: 2
        $x_2_8 = "32695433-4A21-4B67-9FC2-C5340550865E" ascii //weight: 2
        $x_2_9 = "E9799018-D718-47AC-8C2E-DEB93F279F15" ascii //weight: 2
        $x_2_10 = "DD5783BCF1E9002BC00AD5B83A95ED6E4EBB4AD5" ascii //weight: 2
        $x_2_11 = "SYSDOWN.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

