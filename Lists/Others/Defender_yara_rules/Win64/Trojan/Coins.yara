rule Trojan_Win64_Coins_MK_2147959565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.MK!MTB"
        threat_id = "2147959565"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "KeyLogger Error: Logs directory not found or empty." ascii //weight: 5
        $x_5_2 = "Received command: START_REVERSE_SHELL" ascii //weight: 5
        $x_5_3 = "Received command: STOP_REVERSE_SHELL" ascii //weight: 5
        $x_5_4 = "Received command: SEND_REVERSE_SHELL" ascii //weight: 5
        $x_5_5 = "Expircy:" ascii //weight: 5
        $x_5_6 = "Cookies Browser:" ascii //weight: 5
        $x_5_7 = "password collection complete. Uploading ZIP file:" ascii //weight: 5
        $x_2_8 = "BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 2
        $x_2_9 = "Microsoft\\Edge\\User Data" ascii //weight: 2
        $x_1_10 = "Google\\Chrome\\User Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coins_AH_2147964411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coins.AH!MTB"
        threat_id = "2147964411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "nL2@wQ5$pX8zR1mK4cF7hJ0eT3yU6iO9aS2dG5fH8jK1lZ4xC7vB0nM3qW6tY9" ascii //weight: 20
        $x_30_2 = {48 33 c1 48 89 45 00 48 8b 45 08 48 89 45 08 48 8b 45 08 48 8b 4d 00 48 33 c8 48 89 4d 00 eb}  //weight: 30, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

