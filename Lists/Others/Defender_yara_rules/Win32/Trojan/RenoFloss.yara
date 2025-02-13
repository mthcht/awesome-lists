rule Trojan_Win32_RenoFloss_B_2147725517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RenoFloss.B!dha"
        threat_id = "2147725517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RenoFloss"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 ff ff ff ff ?? ?? ?? ?? ?? ?? ?? 31 ?? 10 03 ?? 10 83 ?? fc 0a 00 90 90 ?? ?? ?? c9 66 b9 ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

