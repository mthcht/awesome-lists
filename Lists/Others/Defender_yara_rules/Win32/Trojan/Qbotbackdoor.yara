rule Trojan_Win32_Qbotbackdoor_2147742721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qbotbackdoor!MTB"
        threat_id = "2147742721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbotbackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e0 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 69 7d f0 ?? ?? ?? ?? 89 7d f0 83 c0 01 8b 7d ec 39 f8 89 45 e0 75}  //weight: 2, accuracy: Low
        $x_1_2 = "assholetrackingxavierQ2010.94wthebe" ascii //weight: 1
        $x_1_3 = "jYeshas2" ascii //weight: 1
        $x_1_4 = "thevy112233" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

