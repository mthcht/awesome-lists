rule TrojanDownloader_Win64_Kazy_ARA_2147914691_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Kazy.ARA!MTB"
        threat_id = "2147914691"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Kazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/VERYSILENT_/SUPRESSMSGBOXES_/NORESTART_/UPDATE" ascii //weight: 2
        $x_2_2 = ".rackcdn.com/" ascii //weight: 2
        $x_2_3 = "/addon/v-bates.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

