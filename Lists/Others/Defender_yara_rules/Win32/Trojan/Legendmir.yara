rule Trojan_Win32_Legendmir_MA_2147901714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Legendmir.MA!MTB"
        threat_id = "2147901714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Legendmir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 64 4a 9b 75 5e 7f 2c 3b 51 79 2f 35 38 49 c1 b0 0b db a1 bf 8b 99 ba 07 27 8b 4a d6 69 28 4d}  //weight: 1, accuracy: High
        $x_1_2 = {47 91 1b df 6b 57 ac ae b3 f3 a1 c6 1d db ae 41 d5 ec db ab 50 da 72 20 1b 1e 59 75 d0 cf ed f4}  //weight: 1, accuracy: High
        $x_1_3 = {02 06 c1 7f 02 ca d2 17 d1 a3 1d 26 aa 42 a1 0a e6 f3 39 ab 3d b6 d6 3b 8f 3a 14 58 c6 1d 1d 1d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Legendmir_NL_2147903015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Legendmir.NL!MTB"
        threat_id = "2147903015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Legendmir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 15 f8 70 40 00 85 c0 a3 ?? ?? ?? ?? 74 15 e8 86 02 00 00 85 c0 75 0f ff 35 20 8e 40 00}  //weight: 3, accuracy: Low
        $x_3_2 = {ff 15 04 71 40 00 3b c7 74 61 83 05 08 8e 40 00 10 a3 ?? ?? ?? ?? a1 18 8e 40 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

