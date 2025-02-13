rule Trojan_Win32_BrakeCheck_A_2147822536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BrakeCheck.A!dha"
        threat_id = "2147822536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BrakeCheck"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {83 e0 01 83 e8 01 f7 d0 89 ?? ?? 8b ?? ?? d1 e9 8b ?? ?? 23 ?? ?? 33 ca 89 ?? ?? eb}  //weight: 100, accuracy: Low
        $x_100_2 = {68 41 85 99 ad 68 19 81 38 86 68 5f d7 f1 88 e8}  //weight: 100, accuracy: High
        $x_100_3 = {68 d1 71 05 ad 68 36 6a 1f e1 68 59 81 7e ad e8}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

