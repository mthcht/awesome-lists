rule Trojan_Win32_Wraithbot_AWR_2147966572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wraithbot.AWR!MTB"
        threat_id = "2147966572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wraithbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6b c1 28 6a 00 8b 4c 28 24 ff 74 28 28 8d 04 19 50 8b 44 24 20 03 c1 50 ff 74 24 28 ff d6 8b 4c 24 10 0f b7 47 06 41 89 4c 24 10}  //weight: 4, accuracy: High
        $x_3_2 = "wraithbot.net" wide //weight: 3
        $x_1_3 = "botkiller_scan" ascii //weight: 1
        $x_1_4 = "botkiller_clean" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

