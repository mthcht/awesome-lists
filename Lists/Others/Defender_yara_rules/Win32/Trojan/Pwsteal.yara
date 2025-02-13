rule Trojan_Win32_Pwsteal_Q_2147714345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pwsteal.Q!bit"
        threat_id = "2147714345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pwsteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 d1 ea 66 8b 44 55 ?? 66 89 04 5e 43 3b df 0a 00 e8 ?? ?? ?? ?? 33 d2 6a ?? 59}  //weight: 1, accuracy: Low
        $x_1_2 = {05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 0a 00 69 05 ?? ?? ?? ?? fd 43 03 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 6c 66 89 85 ?? fe ff ff 58 6a 77 66 89 85 ?? fe ff ff 58 6a 61 66 89 85 ?? fe ff ff 58 6a 70 66 89 85 ?? fe ff ff 58 6a 69 66 89 85 ?? fe ff ff 58 66 89 85 ?? fe ff ff 33 c0 66 89 85 ?? fe ff ff ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

