rule TrojanDownloader_MSIL_Minuplo_A_2147692362_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Minuplo.A"
        threat_id = "2147692362"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Minuplo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Projects\\MiniUpload.net\\Apps" ascii //weight: 1
        $x_1_2 = "premiumhesaplarim.net" wide //weight: 1
        $x_1_3 = "lalaker1.net" wide //weight: 1
        $x_1_4 = "/market.php?t=" wide //weight: 1
        $x_1_5 = "pages/create/?ref_type=registration_form" wide //weight: 1
        $x_1_6 = "Reklam\\Update2013\\obj" ascii //weight: 1
        $x_1_7 = "miniupload.net/ir/s2.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

