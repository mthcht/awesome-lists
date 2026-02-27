rule Trojan_Win64_TelegramRAT_AH_2147963791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TelegramRAT.AH!MTB"
        threat_id = "2147963791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TelegramRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Data collection completed. Self-destruction initiated." ascii //weight: 30
        $x_20_2 = "Stealer activated on:" ascii //weight: 20
        $x_10_3 = "self_delete.bat" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

