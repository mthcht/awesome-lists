rule Trojan_Win32_Acbot_A_2147653744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Acbot.A"
        threat_id = "2147653744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Acbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 e1 00 20 00 00 74 24 8b 95 ec f7 ff ff 0f b6 02 83 e0 38 75 0c c7 85 f0 f7 ff ff 00 18 00 00 eb 0a}  //weight: 2, accuracy: High
        $x_2_2 = {68 e9 00 00 00 8b 45 0c 50 e8 ?? ?? ?? ?? 83 c4 08 8b 4d 08 2b 4d 0c 83 e9 05 51 8b 55 0c 83 c2 01 52 e8 ?? ?? ?? ?? 83 c4 08 5d c3}  //weight: 2, accuracy: Low
        $x_2_3 = "msg_id=%s&client_time=%s&to=%s&msg_text=%s&confirmed=1&captcha_pe" ascii //weight: 2
        $x_1_4 = "PROCMON_WINDOW_CLASS" ascii //weight: 1
        $x_1_5 = "*IEXPLORE.EXE" ascii //weight: 1
        $x_1_6 = "WebKit2WebProcess" ascii //weight: 1
        $x_1_7 = "OrderedFriendsList.init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Acbot_B_2147654321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Acbot.B"
        threat_id = "2147654321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Acbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "##STOPMYSPACE##" ascii //weight: 1
        $x_1_2 = "Malekal" ascii //weight: 1
        $x_1_3 = "stophook" ascii //weight: 1
        $x_1_4 = "PROCMON_WINDOW_CLASS" ascii //weight: 1
        $x_1_5 = "SmartSniff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

