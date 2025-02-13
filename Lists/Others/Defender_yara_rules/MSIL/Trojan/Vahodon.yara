rule Trojan_MSIL_Vahodon_A_2147685534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vahodon.A"
        threat_id = "2147685534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "info||" wide //weight: 1
        $x_1_2 = {53 65 6e 64 00 73 00 62 00 52 43 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 42 00 42 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Vahodon_B_2147686215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vahodon.B"
        threat_id = "2147686215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nj-q8" wide //weight: 10
        $x_10_2 = "info||" wide //weight: 10
        $x_10_3 = "microsoft security essentials" wide //weight: 10
        $x_1_4 = "chatback||" wide //weight: 1
        $x_1_5 = "getpw||" wide //weight: 1
        $x_1_6 = "downloadfile||" wide //weight: 1
        $x_1_7 = "FileManager||" wide //weight: 1
        $x_1_8 = {53 65 6e 64 00 73 00 62 00 52 43 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 53 42 00 42 53 00}  //weight: 1, accuracy: High
        $x_1_10 = "cmd.exe /k ping 0 & del \"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Vahodon_C_2147706579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vahodon.C"
        threat_id = "2147706579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nj-q8" wide //weight: 10
        $x_1_2 = "info||myID||" wide //weight: 1
        $x_1_3 = "openurl" wide //weight: 1
        $x_1_4 = "sendfile" wide //weight: 1
        $x_1_5 = "konek" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Vahodon_D_2147716574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Vahodon.D"
        threat_id = "2147716574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vahodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nj-q8" wide //weight: 1
        $x_1_2 = "sendfile" wide //weight: 1
        $x_1_3 = "downloadfile||" wide //weight: 1
        $x_1_4 = {00 53 42 00 42 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

