rule Backdoor_Win32_Wakbot_A_2147665902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wakbot.A"
        threat_id = "2147665902"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 (3e)}  //weight: 2, accuracy: Low
        $x_1_2 = {56 ff 75 ec e8 ?? ?? 00 00 ff 55 (ec)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Wakbot_B_2147665948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Wakbot.B"
        threat_id = "2147665948"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Wakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f7 b1 04 01 00 00 8a 04 3e 8a 14 0a 3a c2 74 09 84 c0 74 05 32 c2 88 04 (3e)}  //weight: 3, accuracy: Low
        $x_1_2 = {8b c2 8b cf 23 c3 83 ef 06 d3 f8 c1 ea 06 85 c0 75 1f}  //weight: 1, accuracy: High
        $x_1_3 = {33 ed 83 c0 04 ba 00 00 fc 00 bf 12 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

