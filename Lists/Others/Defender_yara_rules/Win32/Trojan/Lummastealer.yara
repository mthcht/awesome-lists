rule Trojan_Win32_Lummastealer_MBY_2147940965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummastealer.MBY!MTB"
        threat_id = "2147940965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummastealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 72 64 61 74 61 00 00 20 c9 0b 00 00 70 10 00 00 ca 0b 00 00 62 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 98 14 00 00 00 40 1c 00 00 0a 00 00 00 2c 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 88 03 01 00 00 60 1c 00 00 04 01 00 00 36 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 72 65 6c 6f 63 00 00 c8 bb 00 00 00 70 1d}  //weight: 10, accuracy: High
        $x_10_2 = {2e 74 65 78 74 00 00 00 cd 5b 10 00 00 10 00 00 00 5c 10 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 20 c9 0b 00 00 70 10 00 00 ca 0b 00 00 60 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 98 14 00 00 00 40 1c 00 00 0a 00 00 00 2a 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63}  //weight: 10, accuracy: High
        $x_1_3 = {57 56 89 ce 83 79 04 00 74 52 0f b7 56 0c 66 85 d2 74 0a 66 83 66 0c 00 31 c0 40 eb 54 8d 7e 04}  //weight: 1, accuracy: High
        $x_1_4 = {e9 0a 81 c9 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 81 ca ?? ?? ?? ?? 66 89 56 0c 31 c0 40 89 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

