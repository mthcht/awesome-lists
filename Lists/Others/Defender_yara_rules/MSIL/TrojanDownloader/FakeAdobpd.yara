rule TrojanDownloader_MSIL_FakeAdobpd_A_2147696022_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FakeAdobpd.A"
        threat_id = "2147696022"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeAdobpd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 72 62 6f 72 [0-32] 5c 50 72 6f 6a 65 63 74 73 5c 46 6c 61 73 68 55 70 5c 46 6c 61 73 68 55 70}  //weight: 1, accuracy: Low
        $x_1_2 = "QWRvYmU" wide //weight: 1
        $x_1_3 = "ZmxzaDMyLmN2Yw==" wide //weight: 1
        $x_1_4 = "aHR0cDovL" wide //weight: 1
        $x_1_5 = "U2V0dXAgTG9ncw==" wide //weight: 1
        $x_1_6 = "\\Update Log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_FakeAdobpd_A_2147696022_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/FakeAdobpd.A"
        threat_id = "2147696022"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeAdobpd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovLzE3Ni41OC4xMTUuMTIv" wide //weight: 1
        $x_1_2 = "Update:Update" wide //weight: 1
        $x_1_3 = "schtasks /create /sc onlogon /tn {0} /rl highest" wide //weight: 1
        $x_1_4 = "Yzpcd2luZG93c1xhZG9iZTMyLmV4ZQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

