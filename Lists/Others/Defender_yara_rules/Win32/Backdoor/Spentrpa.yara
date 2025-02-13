rule Backdoor_Win32_Spentrpa_A_2147626361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spentrpa.A"
        threat_id = "2147626361"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spentrpa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d5 8d 54 24 14 68 ?? ?? ?? ?? 52 88 5c 04 1c e8 ?? ?? ?? ?? 83 c4 08 3b c3 74 a2}  //weight: 1, accuracy: Low
        $x_1_2 = {68 a8 61 00 00 51 52 ff d6 8b 15 ?? ?? ?? ?? 6a 00 8b 44 24 0c 8d 4c 24 10 50 51 52 ff d7}  //weight: 1, accuracy: Low
        $x_1_3 = {eb ca 8b 4c 24 18 3b cb 74 29 8a 41 ff 3a c3 74 18 3c ff 74 14 fe c8 5f 5e 88 41 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

