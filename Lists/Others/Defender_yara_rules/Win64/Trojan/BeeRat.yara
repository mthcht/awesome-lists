rule Trojan_Win64_BeeRat_DA_2147934014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BeeRat.DA!MTB"
        threat_id = "2147934014"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BeeRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Screenshot" ascii //weight: 1
        $x_1_2 = "main.readfile" ascii //weight: 1
        $x_1_3 = "main.writetofile" ascii //weight: 1
        $x_1_4 = "main.telegramNotification" ascii //weight: 1
        $x_1_5 = "telegram-bot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

