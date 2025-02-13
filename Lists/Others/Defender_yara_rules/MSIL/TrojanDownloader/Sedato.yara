rule TrojanDownloader_MSIL_Sedato_ARA_2147836263_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Sedato.ARA!MTB"
        threat_id = "2147836263"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sedato"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebClient" ascii //weight: 1
        $x_1_2 = "DownloadFileAsync" ascii //weight: 1
        $x_3_3 = "https://seedauto.net/web" ascii //weight: 3
        $x_2_4 = "https://360seedauto.online/update/capnhat.php" ascii //weight: 2
        $x_2_5 = "https://360seedauto.online/update/SeedAuto.zip" ascii //weight: 2
        $x_1_6 = "powershell.exe" ascii //weight: 1
        $x_1_7 = "ProcessStartInfo" ascii //weight: 1
        $x_1_8 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_9 = "set_UseShellExecute" ascii //weight: 1
        $x_1_10 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

