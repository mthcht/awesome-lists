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

