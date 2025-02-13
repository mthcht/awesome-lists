rule Trojan_WinNT_Kernelpatch_A_2147627779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kernelpatch.A"
        threat_id = "2147627779"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kernelpatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 89 45 d0 60 f5 61 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 dc 8b 00 8b 4d d0 8b 55 d4 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 1, accuracy: High
        $x_1_2 = {83 4d fc ff 8b 17 a1 ?? ?? ?? ?? 39 50 08 77 ?? c7 45 e4 0d 00 00 c0 e9 ?? ?? ?? ?? 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 65 e4 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_WinNT_Kernelpatch_B_2147656880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kernelpatch.B"
        threat_id = "2147656880"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kernelpatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e9 34 01 00 00 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 a5 6c ff ff ff 00 e9 09 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 43 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4e 00 66 c7 85 ?? ff ff ff 54 00 66 c7 85 ?? ff ff ff 5c 00 66 c7 85 ?? ff ff ff 43 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Kernelpatch_C_2147660094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Kernelpatch.C"
        threat_id = "2147660094"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Kernelpatch"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 4d fc ff 8b 17 a1 ?? ?? ?? ?? 39 50 08 77 ?? c7 [0-5] 0d 00 00 c0 e9 ?? ?? ?? ?? 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 [0-5] 00 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 43 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

