rule Trojan_Win64_SeaMonkey_AMS_2147970850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SeaMonkey.AMS!MTB"
        threat_id = "2147970850"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SeaMonkey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 15 b8 99 02 00 48 8d 0d c9 99 02 00 e8 ?? ?? ?? ?? 84 c0 0f 84 85 00 00 00 33 c0 c7 44 24 20 c0 d4 01 00 0f 57 c0 c7 44 24 24 88 13 00 00 0f 11 44 24 28 48 8d 4c 24 20 88 44 24 28 48 89 44 24 38 48 c7 44 24 40 0f 00 00 00 48 89 44 24 48}  //weight: 3, accuracy: Low
        $x_2_2 = "CheckForUpdates" ascii //weight: 2
        $x_1_3 = "pcName" ascii //weight: 1
        $x_1_4 = "userName" ascii //weight: 1
        $x_1_5 = "domainName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

