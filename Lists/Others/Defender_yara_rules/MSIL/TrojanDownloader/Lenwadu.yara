rule TrojanDownloader_MSIL_Lenwadu_A_2147728042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lenwadu.A!bit"
        threat_id = "2147728042"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lenwadu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://u.lewd.se/" wide //weight: 2
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "scvhost" wide //weight: 1
        $x_1_4 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Lenwadu_B_2147728103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lenwadu.B!bit"
        threat_id = "2147728103"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lenwadu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://u.lewd.se/" wide //weight: 2
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "SandboxieRpcSs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Lenwadu_C_2147728268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Lenwadu.C!bit"
        threat_id = "2147728268"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lenwadu"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6e 00 64 00 61 00 6e 00 63 00 65 00 6b 00 61 00 72 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

