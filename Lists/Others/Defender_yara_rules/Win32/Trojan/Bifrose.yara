rule Trojan_Win32_Bifrose_SP_2147837735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bifrose.SP!MTB"
        threat_id = "2147837735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifrose"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 6a 4e ff d7 8b d0 8d 8d 60 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 5c ff ff ff ff d6 50 6a 4d ff d7 8b d0 8d 8d 58 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 54 ff ff ff ff d6 50 6a 52 ff d7 8b d0 8d 8d 50 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 4c ff ff ff ff d6 50 6a 55 ff d7 8b d0 8d 8d 48 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 44 ff ff ff ff d6 50 6a 35 ff d7 8b d0 8d 8d 40 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 3c ff ff ff ff d6 50 6a 53 ff d7 8b d0 8d 8d 38 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 34 ff ff ff ff d6 50 6a 52 ff d7 8b d0 8d 8d 30 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 2c ff ff ff ff d6 50 6a 55 ff d7 8b d0 8d 8d 28 ff ff ff ff d6 50 ff d3 8b d0 8d 8d 24 ff ff ff ff d6 50 6a 73}  //weight: 3, accuracy: High
        $x_1_2 = "adsNOYidGVpIc" wide //weight: 1
        $x_1_3 = "lSkVaAomgyvRoMR" wide //weight: 1
        $x_1_4 = "LrABzEpiqThgwAC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

