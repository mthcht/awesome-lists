rule Trojan_Win32_Sinowal_A_2147593227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sinowal.gen!A"
        threat_id = "2147593227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 eb ?? 80 f1 ?? 88 08 40 8a 08 84 c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 00 00 55 8b}  //weight: 1, accuracy: High
        $x_1_3 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sinowal_B_2147630523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sinowal.gen!B"
        threat_id = "2147630523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 3a 50 45 00 00 74 04 32 c0 eb ?? 8b 45 f0 83 c0 04 89 45 f0 8b 4d f0 83 c1 14 89 4d f8 8b 55 f8 0f b7 02 3d 0b 01 00 00 74}  //weight: 5, accuracy: Low
        $x_1_2 = {83 ec 44 c7 45 fc ff ff ff ff c7 45 bc 00 00 00 00 83 7d bc ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 bc 00 00 00 00 eb 09 8b 4d bc 83 c1 01}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 bc 83 c0 01 89 45 bc}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 fc 0f af 45 fc 83 c0 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

