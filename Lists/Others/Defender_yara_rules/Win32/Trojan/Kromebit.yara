rule Trojan_Win32_Kromebit_A_2147696317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kromebit.A"
        threat_id = "2147696317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kromebit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b3 63 52 50 88 5c 24 34 c6 44 24 35 68 c6 44 24 36 72 c6 44 24 37 6f c6 44 24 38 6d c6 44 24 39 65 c6 44 24 3a 2e c6 44 24 3b 65 c6 44 24 3c 78 c6 44 24 3d 65 c6 44 24 3e 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kromebit_B_2147696318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kromebit.B"
        threat_id = "2147696318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kromebit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b3 72 52 55 c6 44 24 34 63 c6 44 24 35 68 88 5c 24 36 c6 44 24 37 6f c6 44 24 38 6d c6 44 24 39 65 c6 44 24 3a 2e c6 44 24 3b 65 c6 44 24 3c 78 c6 44 24 3d 65 c6 44 24 3e 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

