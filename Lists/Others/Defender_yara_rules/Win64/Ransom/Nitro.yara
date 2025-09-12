rule Ransom_Win64_Nitro_YBH_2147952155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Nitro.YBH!MTB"
        threat_id = "2147952155"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Nitro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "encrypted by our advanced attack" ascii //weight: 10
        $x_10_2 = "How to Buy Bitcoin?" ascii //weight: 10
        $x_10_3 = "Telegram ID" ascii //weight: 10
        $x_1_4 = "Do not use third-party tools" ascii //weight: 1
        $x_1_5 = "HOW-TO-RESTORE-YOUR-FILES.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

