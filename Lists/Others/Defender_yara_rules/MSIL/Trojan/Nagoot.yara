rule Trojan_MSIL_Nagoot_A_2147707908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nagoot.A"
        threat_id = "2147707908"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nagoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 07 1b 58 06 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 ?? ?? ?? ?? 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nagoot_B_2147712307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nagoot.B!bit"
        threat_id = "2147712307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nagoot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b 64 00 6c 64 00 6d 64 00 67 65 74 5f 62 00 67 65 74 5f 63 00 6e 64 00 6f 64 00 70 64 00 71 64}  //weight: 1, accuracy: High
        $x_1_2 = {73 65 74 5f 62 00 74 64 5f 30 00 77 64 00 78 64 [0-64] 6b 63 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_3 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58}  //weight: 1, accuracy: High
        $x_1_4 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

