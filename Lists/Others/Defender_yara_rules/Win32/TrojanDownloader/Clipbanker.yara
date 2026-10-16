rule TrojanDownloader_Win32_Clipbanker_ARA_2147896558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clipbanker.ARA!MTB"
        threat_id = "2147896558"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clipbanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 00 6a 00 6a 00 8d 85 e6 00 00 00 50 6a 00 6a 00 8d 85 d7 05 00 00 ff 10}  //weight: 2, accuracy: High
        $x_2_2 = "w32.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

