rule Trojan_Win32_Prikormka_A_2147720132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prikormka.A"
        threat_id = "2147720132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prikormka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 28 c6 84 24 ?? ?? ?? ?? 1b c6 84 24 ?? ?? ?? ?? 1e c6 84 24 ?? ?? ?? ?? 1f c6 84 24 ?? ?? ?? ?? 2b c6 84 24 ?? ?? ?? ?? 1d c6 84 24 ?? ?? ?? ?? 2c c6 84 24 ?? ?? ?? ?? 21 c6 84 24 ?? ?? ?? ?? 26 c6 84 24 ?? ?? ?? ?? 00 8d 84 24 ?? ?? ?? ?? 59 00 08 40 80 38 00 75 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {88 07 eb 09 8a 54 39 ff 32 d0 88 14 39 41 3b cb 72 db 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

