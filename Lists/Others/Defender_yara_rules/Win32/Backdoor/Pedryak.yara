rule Backdoor_Win32_Pedryak_A_2147622437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Pedryak.A!dll"
        threat_id = "2147622437"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Pedryak"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {05 04 fc ff ff 3d c8 00 00 00 0f 87 ?? 00 00 00 33 c9 8a 88 ?? ?? 00 10 ff 24 8d ?? ?? 00 10 e8 ?? ?? 00 00 c3}  //weight: 3, accuracy: Low
        $x_3_2 = {3d 64 23 00 00 7f ?? ?? ?? 3d 14 05 00 00 7f}  //weight: 3, accuracy: Low
        $x_2_3 = {8b 30 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 ff 15 ?? ?? 00 10 39 44 24 1c 75 0d 68 e0 93 04 00 ff 15 ?? ?? 00 10 eb bc b9}  //weight: 2, accuracy: Low
        $x_1_4 = {83 f8 33 7f 0c 8a c8 80 c1 47 88 0e 83 f8 33 7e 0c 83 f8 3e 7d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {6e 65 74 6d 61 6e 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = "Accept-Language: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

