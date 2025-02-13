rule Trojan_Win32_Tinukebot_DF_2147798522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinukebot.DF!MTB"
        threat_id = "2147798522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 c8 33 d2 f7 75 14 8b 45 10 8a 04 02 32 04 0b 88 01 50 33 c0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

