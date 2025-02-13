rule TrojanDownloader_MSIL_BrobanDel_A_2147691409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BrobanDel.A"
        threat_id = "2147691409"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrobanDel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\downloads\\" ascii //weight: 1
        $x_1_2 = "downloader.exe" ascii //weight: 1
        $x_1_3 = {44 65 63 72 69 70 74 61 72 00 48 65 78 79 00 43 72 79 70 74}  //weight: 1, accuracy: High
        $x_1_4 = {5c 00 61 00 2e 00 64 00 6c 00 6c 00 [0-6] 77 00 69 00 6e 00 64 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_5 = "696F6E5C5C52756E" wide //weight: 1
        $x_1_6 = {5c 00 67 00 62 00 70 00 6c 00 75 00 67 00 69 00 6e 00 [0-16] 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = "5C6762636C617373322E646C6C" wide //weight: 1
        $x_1_8 = {6c 00 69 00 6e 00 6b 00 3d [0-8] 64 00 6e 00 73 00 3d [0-8] 5c 00 61 00 2e 00 64 00 6c 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_BrobanDel_C_2147719133_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BrobanDel.C!bit"
        threat_id = "2147719133"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrobanDel"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XHdpbmxvZy5sb2c=" ascii //weight: 1
        $x_1_2 = "U09GVFdBUkVcQ2xhc3Nlc1xtc2NmaWxlXHNoZWxsXG9wZW5cY29tbWFuZA==" ascii //weight: 1
        $x_1_3 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" ascii //weight: 1
        $x_1_4 = "TWljb3Jzb2Z0IFVzZXIgU2V2cmljZQ==" ascii //weight: 1
        $x_1_5 = "Y21kIC9jIHBpbmcgMS4xLjEuMSAtbiAxIC13IDMwMDAgPiBOdWwgJiBEZWwgIg==" ascii //weight: 1
        $x_1_6 = "Ijpab25lLklkZW50aWZpZXIi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

