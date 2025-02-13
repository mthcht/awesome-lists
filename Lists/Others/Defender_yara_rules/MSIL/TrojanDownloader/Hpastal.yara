rule TrojanDownloader_MSIL_Hpastal_A_2147686017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Hpastal.A"
        threat_id = "2147686017"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hpastal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiVirtualBox" ascii //weight: 1
        $x_1_2 = "AntiWireshark" ascii //weight: 1
        $x_1_3 = "AntiOllydbg" ascii //weight: 1
        $x_1_4 = "AntiKaspersky" ascii //weight: 1
        $x_1_5 = "AntiVirtualPC" ascii //weight: 1
        $x_1_6 = "ChromePass.txt" wide //weight: 1
        $x_1_7 = "foxpass.txt" wide //weight: 1
        $x_1_8 = "operapass.txt" wide //weight: 1
        $x_1_9 = "iepass.txt" wide //weight: 1
        $x_1_10 = "msnpass.txt" wide //weight: 1
        $x_10_11 = "|split|" wide //weight: 10
        $x_10_12 = "zlclient" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

