rule Trojan_Win32_Selfrep_DJ_2147830042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Selfrep.DJ!MTB"
        threat_id = "2147830042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Selfrep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 ec 83 c2 01 89 55 ec 81 7d ec 10 27 00 00 73 19 e8 ?? ?? ?? ?? 99 b9 ff 00 00 00 f7 f9 8b 45 ec 88 94 05 ?? ?? ?? ?? eb d5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 d0 83 c2 01 89 55 d0 81 7d d0 ?? ?? ?? ?? 73 19 e8 ?? ?? ?? ?? 99 b9 ff 00 00 00 f7 f9 8b 45 d0 88 94 05 ?? ?? ?? ?? eb d5}  //weight: 1, accuracy: Low
        $x_5_3 = {81 c2 20 a1 07 00 89 55 a8 6a 00 8d 55 c0 52 8b 45 a8 50 8d 8d ?? ?? ?? ?? 51 8b 55 f0 52 ff 15}  //weight: 5, accuracy: Low
        $x_5_4 = {69 48 18 fd 43 03 00 81 c1 c3 9e 26 00 89 48 18 c1 e9 10 81 e1 ff 7f 00 00 8b c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

