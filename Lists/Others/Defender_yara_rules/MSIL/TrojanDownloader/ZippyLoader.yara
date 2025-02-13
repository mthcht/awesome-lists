rule TrojanDownloader_MSIL_ZippyLoader_BB_2147830408_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ZippyLoader.BB!MTB"
        threat_id = "2147830408"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZippyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gamingfiles.s3.ap-south-1.amazonaws.com" wide //weight: 2
        $x_2_2 = "ConsoleExample\\obj\\Release\\Loader.pdb" ascii //weight: 2
        $x_2_3 = "32bit.exe" wide //weight: 2
        $x_2_4 = "client.bin" wide //weight: 2
        $x_1_5 = "injected successfully" wide //weight: 1
        $x_1_6 = "decrypt_string" ascii //weight: 1
        $x_1_7 = "load_user_data" ascii //weight: 1
        $x_1_8 = "DownloadInject" ascii //weight: 1
        $x_1_9 = "Logging in with saved key" wide //weight: 1
        $x_1_10 = "$4714d95c-1408-44a8-a503-681878bbe3f4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

