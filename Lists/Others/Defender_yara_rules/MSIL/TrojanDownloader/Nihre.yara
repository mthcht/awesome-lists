rule TrojanDownloader_MSIL_Nihre_A_2147647740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nihre.A"
        threat_id = "2147647740"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nihre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nircmd" wide //weight: 1
        $x_1_2 = "win hide ititle" wide //weight: 1
        $x_1_3 = "beattrojan" wide //weight: 1
        $x_1_4 = "werfault" wide //weight: 1
        $x_1_5 = {48 69 64 65 57 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = "de76763f-9a01-4ebd-99dc-362bbb285992" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

