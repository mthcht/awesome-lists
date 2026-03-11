rule Trojan_Win64_DiscordRat_CQ_2147964511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DiscordRat.CQ!MTB"
        threat_id = "2147964511"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DiscordRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8a 04 13 41 80 f0 5a 44 88 04 01 48 ff c0 48 ff c2 48 39 d7 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = "NEW VICTIM DETECTED" ascii //weight: 1
        $x_1_3 = "wifi_passwords.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

