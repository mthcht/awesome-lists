rule TrojanDownloader_MSIL_Craxfora_A_2147706108_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Craxfora.A"
        threat_id = "2147706108"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Craxfora"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {47 5f 4e 6f 6d 65 41 72 71 44 65 73 74 69 6e 6f 49 6e 69 63 69 61 72 00}  //weight: 5, accuracy: High
        $x_5_2 = {46 75 6e 63 5f 43 6f 6e 65 78 00}  //weight: 5, accuracy: High
        $x_5_3 = {46 75 6e 63 5f 54 65 6d 4f 43 61 72 61 00}  //weight: 5, accuracy: High
        $x_5_4 = {46 75 6e 63 5f 41 72 72 6f 78 61 00}  //weight: 5, accuracy: High
        $x_5_5 = "select guarda1 from ropeiro" wide //weight: 5
        $x_5_6 = "INSERT INTO tbl_avs values (@id_pc,@versao,0,0,@ggbb,0,0,0,0,0,@data)" wide //weight: 5
        $x_1_7 = "SQL5009.Smarterasp.net" wide //weight: 1
        $x_1_8 = "Evestern.exe" wide //weight: 1
        $x_1_9 = "myKey123" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*))) or
            (all of ($x*))
        )
}

