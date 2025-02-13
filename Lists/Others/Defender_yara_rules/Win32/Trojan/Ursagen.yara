rule Trojan_Win32_Ursagen_A_2147739937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursagen.A"
        threat_id = "2147739937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursagen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 45 d0 50 6a 00 8d 8d 78 ff ff ff 51 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8d 95 50 f1 ff ff 52 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 45 b8 50 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 8d 4d c4 51 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8d 4d f3 51 ff 15 ?? ?? ?? ?? 68 44 d1 43 00 68 a0 f2 4b 00 e8 58 20 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

