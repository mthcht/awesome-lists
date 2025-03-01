rule TrojanDownloader_MSIL_Coinminer_RS_2147833243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Coinminer.RS!MTB"
        threat_id = "2147833243"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell -Command Add-MpPreference -ExclusionPath" wide //weight: 5
        $x_1_2 = "logs.uce" wide //weight: 1
        $x_1_3 = "Vmtoolsd" wide //weight: 1
        $x_1_4 = "vboxservice" wide //weight: 1
        $x_5_5 = "193.106.191.16" wide //weight: 5
        $x_1_6 = "xmrig.exe" wide //weight: 1
        $x_1_7 = "ethermine" wide //weight: 1
        $x_1_8 = "nanopool" wide //weight: 1
        $x_1_9 = "lolMiner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

