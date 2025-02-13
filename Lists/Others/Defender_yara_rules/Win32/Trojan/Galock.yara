rule Trojan_Win32_Galock_A_2147679913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Galock.A"
        threat_id = "2147679913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Galock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 6a 00 6a 00 6a 00 6a 00 6a ff 8b ?? ?? 08 01 01 01 01 01 01 01 01 50 51 52 53 54 55 56 57 ff 55 ?? 6a 32 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4c 10 18 89 4d ?? 8b 55 ?? 8b 45 ?? 03 42 60 89 45 ?? 8b 4d 0c c1 e9 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

