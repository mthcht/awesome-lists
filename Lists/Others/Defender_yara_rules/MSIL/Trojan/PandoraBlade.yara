rule Trojan_MSIL_PandoraBlade_ASG_2147813843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PandoraBlade.ASG!MSR"
        threat_id = "2147813843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PandoraBlade"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "120"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "stnemhcatta/moc.ppadrocsid.ndc" ascii //weight: 100
        $x_2_2 = {62 00 69 00 6e 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 53 00 4c 00 4e 00 [0-48] 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 [0-48] 2e 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_3 = {62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e [0-48] 6f 62 6a 5c 44 65 62 75 67 [0-48] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_5_4 = "DownloadData" ascii //weight: 5
        $x_5_5 = "Invoke" ascii //weight: 5
        $x_5_6 = "WebClient" ascii //weight: 5
        $x_5_7 = "System.Net" ascii //weight: 5
        $x_1_8 = "Login" ascii //weight: 1
        $x_1_9 = "Password" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 3 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 4 of ($x_5_*))) or
            (all of ($x*))
        )
}

