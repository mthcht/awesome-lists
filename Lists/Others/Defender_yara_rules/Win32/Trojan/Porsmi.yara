rule Trojan_Win32_Porsmi_2147605704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Porsmi"
        threat_id = "2147605704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Porsmi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 38 ff 75 3c 8b 45 f8 80 78 01 fe 75 33}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 07 00 00 00 55 50 5f 57 4f 52 4d 00}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff ff ff 05 00 00 00 63 69 73 68 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff ff ff 07 00 00 00 74 63 70 69 70 2e 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Porsmi_A_2147606678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Porsmi.gen!A"
        threat_id = "2147606678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Porsmi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {75 05 89 45 dc eb 59 6a 00 56 8b 4d 0c 51 57 53 ff 15 ?? ?? ?? ?? 85 c0 75 05 89 45 dc eb 41}  //weight: 5, accuracy: Low
        $x_3_2 = {74 63 70 69 70 2e 6c 00}  //weight: 3, accuracy: High
        $x_1_3 = {70 6f 72 74 61 62 6c 65 6d 73 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 63 70 69 70 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

