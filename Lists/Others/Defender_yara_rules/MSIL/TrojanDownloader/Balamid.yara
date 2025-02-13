rule TrojanDownloader_MSIL_Balamid_A_2147685077_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wintask16.com" ascii //weight: 1
        $x_1_2 = "\\lsm.exe" ascii //weight: 1
        $x_1_3 = "baglanmadi" ascii //weight: 1
        $x_1_4 = "/exc2.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Balamid_A_2147685077_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wintask32.com" ascii //weight: 1
        $x_1_2 = "\\lsm.exe" ascii //weight: 1
        $x_1_3 = "baglanmadi" ascii //weight: 1
        $x_1_4 = "/exc2.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Balamid_A_2147685077_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wintask64.com" ascii //weight: 1
        $x_1_2 = "\\lsm.exe" ascii //weight: 1
        $x_1_3 = "baglanmadi" ascii //weight: 1
        $x_1_4 = "/exc2.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Balamid_A_2147685077_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 77 69 6e 74 61 73 6b 02 00 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 01 00 00 01 00 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_MSIL_Balamid_A_2147685077_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wintask64.com" ascii //weight: 1
        $x_1_2 = "\\task64.exe" ascii //weight: 1
        $x_1_3 = "baglanmadi" ascii //weight: 1
        $x_1_4 = "/toy2.txt" ascii //weight: 1
        $x_1_5 = "\\lsm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_MSIL_Balamid_A_2147685077_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.A"
        threat_id = "2147685077"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\lsm.exe" ascii //weight: 1
        $x_1_2 = "baglanmadi" ascii //weight: 1
        $x_2_3 = "wintask64.com" ascii //weight: 2
        $x_1_4 = "/exc2.txt" ascii //weight: 1
        $x_1_5 = "/dl.txt" ascii //weight: 1
        $x_1_6 = "/url.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Balamid_B_2147687471_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.B"
        threat_id = "2147687471"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "svchostnew.exe" ascii //weight: 10
        $x_10_2 = "ww.wintask16.com/v2.txt" wide //weight: 10
        $x_10_3 = "http://www.wintask16.com/exc2.txt" wide //weight: 10
        $x_1_4 = "\\lsm.exe" wide //weight: 1
        $x_1_5 = "baglanmadi" wide //weight: 1
        $x_1_6 = {73 65 74 5f 50 61 73 73 77 6f 72 64 00 73 65 74 5f 55 73 65 72 6e 61 6d 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Balamid_C_2147705614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Balamid.C"
        threat_id = "2147705614"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\lsm.exe" wide //weight: 1
        $x_1_2 = "/exc2.txt" wide //weight: 1
        $x_1_3 = "baglanmadi" wide //weight: 1
        $x_1_4 = "http://212.129.31.67" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

