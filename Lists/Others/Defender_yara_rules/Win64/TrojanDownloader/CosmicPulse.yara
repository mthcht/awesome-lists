rule TrojanDownloader_Win64_CosmicPulse_BA_2147951583_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/CosmicPulse.BA!dha"
        threat_id = "2147951583"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "machinerie.dll" ascii //weight: 1
        $x_1_2 = "verifyme" ascii //weight: 1
        $x_1_3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/133.0.0.0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

