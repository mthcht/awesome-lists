rule Trojan_Win64_Niugpy_A_2147691550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Niugpy.A"
        threat_id = "2147691550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Niugpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa 7e d2 b1 61 74 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa 78 ea ff ff 8b da 48 8b f9 75 0c}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 f0 00 ff ff 44 8d 81 88 ff 00 00 49 8b ca 41 c1 e0 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Niugpy_B_2147691551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Niugpy.B"
        threat_id = "2147691551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Niugpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa 7e d2 b1 61 74 04}  //weight: 1, accuracy: High
        $x_1_2 = {81 fa 78 ea ff ff 8b da 48 8b f9 75 0c}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 f0 00 ff ff 44 8d 81 88 ff 00 00 49 8b ca 41 c1 e0 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

