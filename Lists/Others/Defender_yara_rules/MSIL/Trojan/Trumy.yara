rule Trojan_MSIL_Trumy_A_2147685480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Trumy.A"
        threat_id = "2147685480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trumy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/program.php" ascii //weight: 1
        $x_1_2 = "get=preferences" ascii //weight: 1
        $x_1_3 = "\\Adobe Flash Player.exe" ascii //weight: 1
        $x_1_4 = "eklenti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Trumy_A_2147685480_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Trumy.A"
        threat_id = "2147685480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trumy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/program.php" ascii //weight: 1
        $x_1_2 = "get=chrome" ascii //weight: 1
        $x_1_3 = "\\chrome.dll" ascii //weight: 1
        $x_1_4 = "eklenti" ascii //weight: 1
        $x_1_5 = "\\Google\\Chrome\\User Data\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

