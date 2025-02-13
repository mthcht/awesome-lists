rule TrojanDownloader_MSIL_Vhoster_A_2147684456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Vhoster.A"
        threat_id = "2147684456"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vhoster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 16 08 16 1f 10 28 20 00 00 0a 09 16 08 1f 0f 1f 10 28 20 00 00 0a 06 08 6f 21 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {13 05 12 05 fe 16 ?? ?? ?? ?? 6f ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0c 73 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 73 ?? ?? ?? ?? 0d 09 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "winhoster" wide //weight: 1
        $x_1_4 = "Npf MZKAjm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

