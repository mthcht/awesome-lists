rule Trojan_Win32_LiteDuke_A_2147752034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LiteDuke.A!dha"
        threat_id = "2147752034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LiteDuke"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 56 57 56 56 56 b8 00 00 00 80 50 56 50 68 00 00 cf 00 56 b9}  //weight: 10, accuracy: High
        $x_10_2 = {68 be dd 54 7e [0-6] e8}  //weight: 10, accuracy: Low
        $x_10_3 = {68 1a 0e 38 59 [0-6] e8}  //weight: 10, accuracy: Low
        $x_10_4 = {40 00 32 11 32 d0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

