rule Trojan_Win32_Bankpatch_A_2147601042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bankpatch.A"
        threat_id = "2147601042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bankpatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 08 8b 40 04 e8 00 00 00 00 5a 8d 92 (20|21) 00 00 00 33 c9 [0-2] 39 02 74 0c 83 c2 04 39 0a 75 f5 e9 ?? ?? ?? ?? 33 c0 48 c2 0c 00 d8 8f 46 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

