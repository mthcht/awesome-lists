rule Trojan_MSIL_Redlonam_A_2147697057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlonam.A"
        threat_id = "2147697057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlonam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rm9sZGVyTmFtZVxmaWxlLmV4ZQ==" ascii //weight: 1
        $x_1_2 = "FolderName\\file.exe" ascii //weight: 1
        $x_1_3 = "ZmlsZS5leGU=" ascii //weight: 1
        $x_1_4 = "file.exe" ascii //weight: 1
        $x_1_5 = "XHRlbXBc" ascii //weight: 1
        $x_1_6 = "\\temp\\" ascii //weight: 1
        $x_1_7 = "bXlTYWx0VmFsdWU=" ascii //weight: 1
        $x_1_8 = "mySaltValue" ascii //weight: 1
        $x_1_9 = "QDFCMmMzRDRlNUY2ZzdIOA==" ascii //weight: 1
        $x_1_10 = "@1B2c3D4e5F6g7H8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Redlonam_B_2147705999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redlonam.B"
        threat_id = "2147705999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redlonam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FolderName\\file.exe" ascii //weight: 1
        $x_1_2 = {00 66 69 6c 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "\\temp\\" ascii //weight: 1
        $x_1_4 = {52 65 67 41 73 6d 2e 65 78 65 00 4d 69 63 72 6f 73 6f 66 74 20 41 63 63 65 73 73 2e 2e 2e 32 30 31 33 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

