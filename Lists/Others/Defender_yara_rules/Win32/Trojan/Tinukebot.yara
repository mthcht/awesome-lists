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

rule Trojan_Win32_Tinukebot_A_2147962355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tinukebot.A!AMTB"
        threat_id = "2147962355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_2_2 = "Send Data Fail" ascii //weight: 2
        $x_1_3 = "\\chrome.txt" ascii //weight: 1
        $x_1_4 = "%s\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_2_5 = "[chrome.txt] scucessful" ascii //weight: 2
        $x_2_6 = "b0R0W@W" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

