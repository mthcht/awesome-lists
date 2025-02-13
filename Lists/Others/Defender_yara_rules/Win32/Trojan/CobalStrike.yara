rule Trojan_Win32_CobalStrike_ATZ_2147920761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CobalStrike.ATZ!MTB"
        threat_id = "2147920761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CobalStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 02 8d ?? ?? 03 c9 2b c1 8a 44 05 f8 30 84 35 c4 a8 fa ff 46 3b f7}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d f8 33 f6 c7 45 f8 71 61 78 7a 66 c7 45 fc 6e 62}  //weight: 1, accuracy: High
        $x_1_3 = {6a 40 68 00 30 00 00 57 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

