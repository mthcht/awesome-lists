rule TrojanDownloader_Win64_Mikey_ARAC_2147851983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Mikey.ARAC!MTB"
        threat_id = "2147851983"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Mikey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 ff c7 f7 eb 8b c2 c1 e8 1f 03 d0 0f b6 c2 02 c0 02 d0 0f b6 c3 ff c3 2a c2 04 02 00 44 37 ff 49 3b f8 7c d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

