rule TrojanDownloader_MSIL_Duplerd_A_2147707440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Duplerd.A"
        threat_id = "2147707440"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Duplerd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "W1dJTjg2X0lEXQ==" ascii //weight: 1
        $x_1_2 = "PFtuQHx8QG5dPg==" ascii //weight: 1
        $x_1_3 = "RExfRVhFQ1VURQ==" ascii //weight: 1
        $x_1_4 = {20 50 4b 03 04 33 ?? 06 1f 2c 58 48 1f 14 33}  //weight: 1, accuracy: Low
        $x_1_5 = "CreateEncryptor" wide //weight: 1
        $x_1_6 = "$3f394690-29cb-4c19-b4da-7edd29b7168e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

