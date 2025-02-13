rule TrojanDownloader_MSIL_Aftudoro_A_2147668194_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Aftudoro.A"
        threat_id = "2147668194"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aftudoro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "175"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\winlogon.com" wide //weight: 100
        $x_30_2 = ".com/wp-admin/images/%20/load.com" wide //weight: 30
        $x_30_3 = ".com/load.exe" wide //weight: 30
        $x_40_4 = "LIMA\\Desktop\\1\\Application1.0\\" ascii //weight: 40
        $x_5_5 = "DownApp\\DownApp\\obj\\x86\\Release\\" ascii //weight: 5
        $x_5_6 = "Baixaai\\Baixaai\\obj\\x86\\Release\\" ascii //weight: 5
        $x_5_7 = "UpdateDownload\\UpdateDownload\\obj\\x86\\Release" ascii //weight: 5
        $x_5_8 = "tramposussa.com/load.exe" wide //weight: 5
        $x_5_9 = "$e387b904-2661-42db-8c8e-2b7096ed7451" ascii //weight: 5
        $x_5_10 = "4507-5678-2eaac48f0c3a" ascii //weight: 5
        $x_1_11 = "UpdateGoogle.pdb" ascii //weight: 1
        $x_1_12 = "DownApp.pdb" ascii //weight: 1
        $x_1_13 = "Winamp_Mode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 3 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 1 of ($x_30_*) and 1 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_40_*) and 2 of ($x_30_*))) or
            (all of ($x*))
        )
}

