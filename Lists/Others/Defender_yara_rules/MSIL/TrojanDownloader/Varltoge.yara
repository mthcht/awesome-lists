rule TrojanDownloader_MSIL_Varltoge_A_2147691914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Varltoge.A"
        threat_id = "2147691914"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Varltoge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "astral2011.96@gmail.com" wide //weight: 2
        $x_2_2 = "stral2011/fake.exe" wide //weight: 2
        $x_2_3 = "h1gh-voltage.ru/h1gh.exe" wide //weight: 2
        $x_2_4 = "h1gh-voltage.ru/spammer.php" wide //weight: 2
        $x_1_5 = "\\temp\\h1gh.exe" wide //weight: 1
        $x_1_6 = "temp\\info.pas.log" wide //weight: 1
        $x_1_7 = "jects\\Stealer\\Stealer\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

