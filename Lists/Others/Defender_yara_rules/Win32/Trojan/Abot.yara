rule Trojan_Win32_Abot_A_2147649025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Abot.gen!A"
        threat_id = "2147649025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Abot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aldibot-by-till7.ch" ascii //weight: 1
        $x_1_2 = {6f 70 48 54 54 50 44 44 6f 53 02 00 53 74}  //weight: 1, accuracy: Low
        $x_1_3 = {6f 70 54 43 50 44 44 6f 53 02 00 53 74}  //weight: 1, accuracy: Low
        $x_1_4 = {6f 70 44 44 6f 53 02 00 53 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

