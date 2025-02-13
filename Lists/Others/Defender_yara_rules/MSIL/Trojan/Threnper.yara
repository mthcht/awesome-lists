rule Trojan_MSIL_Threnper_A_2147684109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Threnper.A"
        threat_id = "2147684109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Threnper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {62 74 63 6d 69 6e 65 72 00 6d 61 69 6e 00 72 65 66 69 6c 6c 73 74 61 72 74 75 70}  //weight: 4, accuracy: High
        $x_4_2 = "-u Thane_Thane" wide //weight: 4
        $x_1_3 = "scvhost.exe" wide //weight: 1
        $x_1_4 = "-o http://eu.triplemining.com:8344" wide //weight: 1
        $x_1_5 = "-p operation11" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Threnper_B_2147684114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Threnper.B"
        threat_id = "2147684114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Threnper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "-u steve_uk@safe-mail.net_serv" wide //weight: 4
        $x_1_2 = "-o http://pool.50btc.com:8332" wide //weight: 1
        $x_1_3 = "scvhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

