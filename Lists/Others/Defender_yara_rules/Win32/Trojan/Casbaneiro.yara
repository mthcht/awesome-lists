rule Trojan_Win32_Casbaneiro_GTR_2147929995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Casbaneiro.GTR!MTB"
        threat_id = "2147929995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Casbaneiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4b 00 33 00 66 00 44 00 64 00 45 00 51 00 53 00 56 00 38 00 56 00 38}  //weight: 5, accuracy: High
        $x_5_2 = {4e 00 42 00 77 00 71 00 39 00 32 00 77}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Casbaneiro_GTN_2147931422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Casbaneiro.GTN!MTB"
        threat_id = "2147931422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Casbaneiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {20 20 20 20 20 20 20 20 00 42 b3 04 00 40 a9 00 00 a6 52}  //weight: 5, accuracy: High
        $x_5_2 = {40 2e 69 64 61 74 61 00 00 00 10 00 00 00 80 89 06 00 06 00 00 00}  //weight: 5, accuracy: High
        $x_10_3 = {40 00 00 40 2e 69 64 61 74 61 00 00 00 10 00 00 00 50 89 06 00 06 00 00 00 22 de}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

