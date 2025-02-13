rule TrojanDownloader_MSIL_MCCrash_NZM_2147836791_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/MCCrash.NZM!MTB"
        threat_id = "2147836791"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MCCrash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 72 31 00 00 70 6f ?? 00 00 0a 25 72 41 00 00 70 6f 0b 00 00 0a 6f 0c 00 00 0a 25 6f 0d 00 00 0a 26}  //weight: 1, accuracy: Low
        $x_1_2 = "Windows/svchost.exe" ascii //weight: 1
        $x_1_3 = "repo.ark-event.net/downloads/svchosts.exe" ascii //weight: 1
        $x_1_4 = "Net.WebClient).DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

