rule TrojanDownloader_Win32_Snojan_BB_2147822995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Snojan.BB!MTB"
        threat_id = "2147822995"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 18 83 78 20 00 75 06 83 78 2c 00 74 26 8b 55 ec 39 50 1c 7f 1e 7c 08 8b 55 e8 39 50 18 73 14 3b 06 75 04 89 1e eb 02 89 1f ff 4e 0c}  //weight: 1, accuracy: High
        $x_1_2 = "wecan.hasthe.technology/upload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

