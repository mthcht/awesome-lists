rule Trojan_Win32_Crix_B_2147652482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crix.B"
        threat_id = "2147652482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 1c 5f f7 ff 8a 82 ?? ?? ?? ?? 30 01 46 3b 75 0c 7e e4}  //weight: 2, accuracy: Low
        $x_1_2 = {7f f7 b9 a9 f1 a7 1f}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff 6a 14 68 ?? ?? ?? ?? e8 ?? ?? ff ff 6a 12 68 ?? ?? ?? ?? e8 ?? ?? ff ff 6a 12 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

