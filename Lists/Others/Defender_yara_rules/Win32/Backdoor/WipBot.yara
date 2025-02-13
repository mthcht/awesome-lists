rule Backdoor_Win32_WipBot_B_2147688612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/WipBot.B"
        threat_id = "2147688612"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "WipBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 3a 88 d0 32 01 42 83 f0 ?? 83 fa ?? 88 01 75 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {8d ba 5f f3 6e 3c 89 fe c1 ee 10 89 f2 30 14 01 40 3b 43 04 72 e4 5b b8 01 00 00 00 5e 5f 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {c7 47 20 90 90 90 90 c7 47 24 90 90 90 c3 c7 47 28 50 51 48 83 c7 47 2c ec 28 48 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

