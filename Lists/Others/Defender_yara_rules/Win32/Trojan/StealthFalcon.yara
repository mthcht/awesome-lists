rule Trojan_Win32_StealthFalcon_E_2147742826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealthFalcon.E!dha"
        threat_id = "2147742826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealthFalcon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8a 44 0e 02 32 44 0e 01 88 04 19 f6 c1 01 75}  //weight: 6, accuracy: High
        $x_6_2 = {8a 56 02 32 d0 88 14 19 41 3b cf 72}  //weight: 6, accuracy: High
        $x_6_3 = {8b 45 08 83 f8 01 76 0a 8d 73 01 8d 48 ff 8b fb f3 a4 8b c3}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

