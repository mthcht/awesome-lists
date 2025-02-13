rule Trojan_MSIL_Beyuwa_A_2147695367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Beyuwa.A"
        threat_id = "2147695367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Beyuwa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 31 00 6b 32 00 6b 33}  //weight: 1, accuracy: High
        $x_1_2 = {42 79 65 00 52 75 6e 41 77 61 79 00 57 68 79}  //weight: 1, accuracy: High
        $x_1_3 = {62 31 00 62 32 00 62 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Beyuwa_A_2147695367_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Beyuwa.A"
        threat_id = "2147695367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Beyuwa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LinkViewer" ascii //weight: 1
        $x_1_2 = "StartUp" ascii //weight: 1
        $x_1_3 = "DownloadList" ascii //weight: 1
        $x_1_4 = "Shuffle" ascii //weight: 1
        $x_1_5 = "DisableClickSounds" ascii //weight: 1
        $x_1_6 = "/nig.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Beyuwa_A_2147695367_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Beyuwa.A"
        threat_id = "2147695367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Beyuwa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 78 01 00 70 a2 09 17 72 86 01 00 70 a2 09 18 72 8a 01 00 70 a2 09 17 6f}  //weight: 2, accuracy: High
        $x_2_2 = {8e 69 2d 02 16 2a 02 02 02 7b}  //weight: 2, accuracy: High
        $x_2_3 = "/nig.txt" wide //weight: 2
        $x_2_4 = "80.242.123.211:888" wide //weight: 2
        $x_1_5 = "/refer.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

