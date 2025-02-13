rule TrojanDownloader_MSIL_PureCrypt_KS_2147912969_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureCrypt.KS!MTB"
        threat_id = "2147912969"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://155.94.210.73/bless.pdf" ascii //weight: 1
        $x_1_2 = {06 72 01 00 00 70 28 29 05 00 06 6f 59 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

