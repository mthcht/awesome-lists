rule Trojan_Win32_Qsbot_A_2147641185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qsbot.A"
        threat_id = "2147641185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qsbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 6d 61 69 6c 74 6f 5b 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 10 66 89 14 06 83 c0 02 66 85 d2 75 f1 6a 00 8d 54 24 0c 52 6a 00 6a 00 68 ?? 0c 00 00 8d 41 04 8b 09 50 68 00 24 22 00 51 ff 15 ?? ?? ?? ?? 85 c0 0f 95 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

