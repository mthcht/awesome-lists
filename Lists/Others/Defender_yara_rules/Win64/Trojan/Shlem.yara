rule Trojan_Win64_Shlem_EH_2147846236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shlem.EH!MTB"
        threat_id = "2147846236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shlem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "NjczZTFhNDAwYzYzNmE3NDJiYjkyMDQ4YTNhOGJkOTZjZTk1" ascii //weight: 10
        $x_10_2 = "Y2VkZWM3ZjY0OWQyNzEwNjdlMGVjYjA5YmUyY2EzYmY" ascii //weight: 10
        $x_1_3 = "WDnsNameCompare" ascii //weight: 1
        $x_1_4 = "TerminateProcessZanabazar_Square" ascii //weight: 1
        $x_1_5 = "adxaesavxendfinfmagc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

