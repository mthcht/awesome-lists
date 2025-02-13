rule TrojanDownloader_MSIL_Nijrecy_A_2147637636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nijrecy.A"
        threat_id = "2147637636"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nijrecy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0c 11 10 20 00 30 00 00 1f 40 28 ?? ?? ?? ?? 13 0d 11 04 16 8f ?? ?? ?? ?? 71 ?? ?? ?? ?? 11 0d 02 11 05 28 ?? ?? ?? ?? b8 11 0e 28}  //weight: 2, accuracy: Low
        $x_1_2 = "PHP Crypter" ascii //weight: 1
        $x_1_3 = "[##]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

