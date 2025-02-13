rule Trojan_Win32_Estiwir_A_2147679094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Estiwir.A"
        threat_id = "2147679094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Estiwir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 01 80 f2 ?? 88 10 40 4e 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c6 ff d0 33 c0 eb 17}  //weight: 1, accuracy: High
        $x_1_3 = {8a 54 38 05 2a d1 88 94 3d ?? ?? ff ff 47 3b 38 72 ee}  //weight: 1, accuracy: Low
        $x_1_4 = "%d%d%d%d%d.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Estiwir_B_2147688173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Estiwir.B"
        threat_id = "2147688173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Estiwir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 06 80 f1 ?? 88 08 40 4f 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = "EstRtwIFDrv" wide //weight: 1
        $x_1_3 = {00 25 64 25 64 25 64 25 64 25 64 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {8a 14 01 80 f2 ?? 88 10 40 4e 75 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

