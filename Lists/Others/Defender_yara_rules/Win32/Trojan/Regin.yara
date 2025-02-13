rule Trojan_Win32_Regin_D_2147692609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Regin.D!dha"
        threat_id = "2147692609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Regin"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e4 10 00 00 00 c7 45 ec 07 00 00 00 c7 45 fc b8 0b 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 6a 05 58 e8 ?? ?? ?? ?? 6a 00 6a 04}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 01 6a 06 58 e8 ?? ?? ?? ?? 6a 00 6a 07 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 01 6a 03 58 e8 ?? ?? ?? ?? 59 6a 01 6a 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 01 6a 02 58 e8 ?? ?? ?? ?? 56 6a 04 58 e8 ?? ?? ?? ?? 59 59 e8 ?? ?? ?? ?? 6a 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

