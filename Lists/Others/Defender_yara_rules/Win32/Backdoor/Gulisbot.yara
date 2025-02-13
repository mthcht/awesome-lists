rule Backdoor_Win32_Gulisbot_A_2147615394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Gulisbot.gen!A"
        threat_id = "2147615394"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Gulisbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 15 8a 83 ?? ?? ?? ?? 55 30 04 3e 43 e8 ?? ?? 00 00 3b d8 59 72 eb 8a 04 3e 57 f6 d0 88 04 3e 46 e8 ?? ?? 00 00 3b f0 59 72 ca}  //weight: 2, accuracy: Low
        $x_2_2 = {99 b9 bf 63 00 00 8b 5d 08 f7 f9 6a 03 89 5d d8 81 ea c0 63 00 00 07 00 75 4c e8 ?? ?? 00}  //weight: 2, accuracy: Low
        $x_2_3 = {75 51 6a 7f ff 74 be 04 68 ?? ?? ?? ?? e8 ?? ?? 00 00 ff 74 be 08 e8 ?? ?? 00 00 6a 1f a3 ?? ?? ?? ?? ff 74 be 0c}  //weight: 2, accuracy: Low
        $x_10_4 = "aspergillus" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

