rule TrojanDownloader_MSIL_Aguadi_A_2147692615_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Aguadi.A"
        threat_id = "2147692615"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aguadi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@8NaMzObLyPcKxQdJwReIvSfHuT6GtUhFsViErWjDqXkCpYlBoZmA453g271n9#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

