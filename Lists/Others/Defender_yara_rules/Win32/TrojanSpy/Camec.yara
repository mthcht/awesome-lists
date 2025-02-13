rule TrojanSpy_Win32_Camec_A_2147637865_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Camec.A"
        threat_id = "2147637865"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1F67565451497C595758441E51434048" wide //weight: 1
        $x_1_2 = "58474D40430A1F1F474747435E1E52425154554353" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Camec_AP_2147652488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Camec.AP"
        threat_id = "2147652488"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7C736D65797B67731B706B7D" wide //weight: 1
        $x_1_2 = "5959525C5B1A595F43501D5B5E5B" wide //weight: 1
        $x_1_3 = "515345505B505058565C5277435F5F5D5E" wide //weight: 1
        $x_1_4 = "66737B7D7414717715767C766577" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Camec_AQ_2147655210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Camec.AQ"
        threat_id = "2147655210"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 95 50 ff ff ff 6a 38 52 ff d6 8d 85 40 ff ff ff 6a 37 50 ff d6 8d 8d 20 ff ff ff 6a 36}  //weight: 2, accuracy: High
        $x_1_2 = {43 61 70 74 63 68 61 5f 44 6f 63 5f 45 6d 70 72 65 73 61 00}  //weight: 1, accuracy: High
        $x_1_3 = "value1=1&value2=2" wide //weight: 1
        $x_1_4 = "--Xu02=$--" wide //weight: 1
        $x_1_5 = "7C736D65797B67731B706B7D" wide //weight: 1
        $x_1_6 = "6E0B6650475D545A15515C1879720218" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Camec_AR_2147655365_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Camec.AR"
        threat_id = "2147655365"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 95 50 ff ff ff 6a 38 52 ff d6 8d 85 40 ff ff ff 6a 37 50 ff d6 8d 8d 20 ff ff ff 6a 36}  //weight: 1, accuracy: High
        $x_1_2 = {43 61 70 74 63 68 61 5f 44 6f 63 5f 45 6d 70 72 65 73 61 00}  //weight: 1, accuracy: High
        $x_1_3 = "--Xu02=$--" wide //weight: 1
        $x_1_4 = "Adobe Flash Player" ascii //weight: 1
        $x_1_5 = "extrato" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

