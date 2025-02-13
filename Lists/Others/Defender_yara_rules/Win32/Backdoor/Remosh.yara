rule Backdoor_Win32_Remosh_A_2147637473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Remosh.gen!A"
        threat_id = "2147637473"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Remosh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 33 f6 39 74 24 0c 7e 1a 8b 4c 24 08 57 8b c6 bf ?? 00 00 00 99 f7 ff 30 11 41 46 3b 74 24 10 7c ec 5f 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {66 89 45 f0 8a 45 10 57 33 ff 84 c0 88 45 f2 88 4d fb c7 45 fc 68 57 24 13 74 3e}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 10 84 c0 74 5c 81 7e 0c 68 57 24 13 75 53 8b 46 03 85 c0 0f 86 93 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

