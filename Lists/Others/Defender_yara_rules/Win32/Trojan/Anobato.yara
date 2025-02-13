rule Trojan_Win32_Anobato_A_2147706366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Anobato.A"
        threat_id = "2147706366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 ff 83 f8 00 74 07 80 7c 03 ff c3 74 06}  //weight: 1, accuracy: High
        $x_1_2 = {31 ff c7 43 04 c2 a5 10 28 31 ff 66 c7 43 02 9c 40 31 ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 89 c7 48 05 00 20 00 00 31 ff 49 89 07 48 05 00 20 00 00 31 ff}  //weight: 1, accuracy: High
        $x_1_4 = {31 ff 48 83 ec 20 48 c7 c1 00 00 00 00 48 c7 c2 00 40 01 00 49 c7 c0 00 30 00 00 49 c7 c1 40 00 00 00 ff 15 ?? ?? ?? ?? 48 83 c4 20 31 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Anobato_A_2147706366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Anobato.A"
        threat_id = "2147706366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Anobato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 bd 40 05 00 00 01 [0-16] 75 ?? [0-16] eb ?? [0-16] c7 85 40 05 00 00 00 00 00 ?? [0-16] eb ?? [0-16] c7 85 40 05 00 00 00 00 00 ?? [0-16] 6a 40 68 00 30 00 00 68 00 (20 00|40 01) 00 6a 00}  //weight: 10, accuracy: Low
        $x_10_2 = {ff b5 a0 05 00 00 68 02 02 00 00 ?? 95 80 04 00 00 6a 06 6a 01 6a 02 ?? 95 c8 04 00 00 89 85 b8 05 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {d0 8b 45 00 83 c0 0c ff 75 10 50 ff (95|15) ?? ?? ?? ?? ff b5 b8 05 00 00 ff 95 90 04 00 00 68 (e8 03|d0 07) 00 00 ff (95|15) ?? ?? ?? ?? ?? ?? ?? ff ff}  //weight: 10, accuracy: Low
        $x_1_4 = "50.7.138.138" ascii //weight: 1
        $x_1_5 = "50.7.124.199" ascii //weight: 1
        $x_1_6 = "149.154.64.167" ascii //weight: 1
        $x_1_7 = "5.8.60.23" ascii //weight: 1
        $x_1_8 = {31 39 33 2e 32 38 2e 31 37 39 2e 01 00 02 00}  //weight: 1, accuracy: Low
        $x_1_9 = "85.93.0.22" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

