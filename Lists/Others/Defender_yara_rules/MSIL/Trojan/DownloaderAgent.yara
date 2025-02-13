rule Trojan_MSIL_DownloaderAgent_S_2147751755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DownloaderAgent.S!MTB"
        threat_id = "2147751755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DownloaderAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "https://download.wetransfer.com//eu2/b6d64ee315e1ebed14a5b2e5f033fad320200316050744/523761a8cec10aca782ede7bec5fe6d93b794d03/" wide //weight: 10
        $x_3_2 = "cf=y&token=" wide //weight: 3
        $x_3_3 = "\\svchost.exe" wide //weight: 3
        $x_3_4 = "TROLLED!!!" wide //weight: 3
        $x_1_5 = "WindowsFormsApp.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

