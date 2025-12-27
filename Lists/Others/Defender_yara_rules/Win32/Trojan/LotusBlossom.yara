rule Trojan_Win32_LotusBlossom_ARA_2147957026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusBlossom.ARA!MTB"
        threat_id = "2147957026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusBlossom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff d7 25 7f 00 00 80 79 05 48 83 c8 80 40 30 44 34 10 46 81 fe 88 04 00 00 72 e5}  //weight: 5, accuracy: High
        $x_2_2 = {ff 15 2c a3 00 10}  //weight: 2, accuracy: High
        $x_2_3 = {ff 15 50 51 00 10}  //weight: 2, accuracy: High
        $x_3_4 = {25 7f 00 00 80 79 05 48 83 c8 80 40 30 84 3d 68 fa ff ff 47 3b fe 72 e2}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LotusBlossom_ARAX_2147959971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusBlossom.ARAX!MTB"
        threat_id = "2147959971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusBlossom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 15 24 a3 00 10 25 7f 00 00 80 79 05 48 83 c8 80 40}  //weight: 2, accuracy: High
        $x_2_2 = {30 84 3d 68 fa ff ff 47 3b fe 72 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

