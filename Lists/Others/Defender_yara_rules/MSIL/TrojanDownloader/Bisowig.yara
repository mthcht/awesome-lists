rule TrojanDownloader_MSIL_Bisowig_A_2147658271_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bisowig.A"
        threat_id = "2147658271"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bisowig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "180"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "things.futurehopesdie.com/msn.exe" wide //weight: 100
        $x_50_2 = "Portable IE 8 PT-BR [By N1gh7w0lf]" wide //weight: 50
        $x_50_3 = "extractie\\iexplore.exe" wide //weight: 50
        $x_20_4 = "PROXY y.futurehopesdie.com" wide //weight: 20
        $x_20_5 = "royalpalmscommunity.com/registrado.php" wide //weight: 20
        $x_10_6 = "Pharming_v10.Resources" wide //weight: 10
        $x_10_7 = "\\temporaryfile.jsp" wide //weight: 10
        $x_10_8 = "wingbiso.txt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 2 of ($x_20_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Bisowig_B_2147658723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bisowig.B"
        threat_id = "2147658723"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bisowig"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DragonMyth" ascii //weight: 5
        $x_5_2 = "Pharming v" ascii //weight: 5
        $x_1_3 = "checkinfect.php" wide //weight: 1
        $x_1_4 = "function FindProxyForURL(url, host)" wide //weight: 1
        $x_1_5 = "//Banco do Brasil" wide //weight: 1
        $x_1_6 = "PROXY y.futurehopesdie.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

