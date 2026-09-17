rule TrojanDownloader_Win64_Donut_RF_2147978381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Donut.RF!MTB"
        threat_id = "2147978381"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://185.177.239.241:5001/miro.bin" ascii //weight: 1
        $x_1_2 = "sosk.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

