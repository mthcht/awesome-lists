rule Trojan_Win32_SentryTome_A_2147724721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SentryTome.A!dha"
        threat_id = "2147724721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SentryTome"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ee c6 44 24 ?? c1 [0-4] c6 44 24 ?? c4 [0-4] c6 44 24 ?? 87 [0-4] c6 44 24 ?? a9 [0-4] c6 44 24 ?? f0}  //weight: 1, accuracy: Low
        $x_1_2 = {fd c6 44 24 ?? 5b [0-4] c6 44 24 ?? 84 [0-4] c6 44 24 ?? 3a [0-4] c6 44 24 ?? 12 [0-4] c6 44 24 ?? d0}  //weight: 1, accuracy: Low
        $x_1_3 = {d0 c6 44 24 ?? cd [0-9] c6 44 24 ?? 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

