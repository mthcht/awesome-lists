rule Trojan_Win64_GOClipper_DA_2147851671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GOClipper.DA!MTB"
        threat_id = "2147851671"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GOClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dynam1c Clipper" ascii //weight: 1
        $x_1_2 = "atotto/clipboard.WriteAll" ascii //weight: 1
        $x_1_3 = "atotto/clipboard.ReadAll" ascii //weight: 1
        $x_1_4 = "telegram-bot-api.NewBotAPI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

