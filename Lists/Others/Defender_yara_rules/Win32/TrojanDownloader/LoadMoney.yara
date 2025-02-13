rule TrojanDownloader_Win32_LoadMoney_ARA_2147897644_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/LoadMoney.ARA!MTB"
        threat_id = "2147897644"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "LoadMoney"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f3 0f b6 44 15 00 30 04 0e 83 c1 01 39 cf 75 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

