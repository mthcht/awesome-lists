rule TrojanDownloader_MSIL_PromCoinminer_A_2147764091_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PromCoinminer.A!MTB"
        threat_id = "2147764091"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PromCoinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mrbfile.xyz/sql/syslib.dll" ascii //weight: 1
        $x_1_2 = "\\SecurityService\\SecurityService\\obj\\Release\\WindowsSecurityService.pdb" ascii //weight: 1
        $x_1_3 = "\\config.json" ascii //weight: 1
        $x_1_4 = "\\version.txt" ascii //weight: 1
        $x_1_5 = "DownloadDLL" ascii //weight: 1
        $x_1_6 = "CopyZipFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

