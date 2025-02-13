rule Trojan_Win32_Kutphish_A_2147741000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.A"
        threat_id = "2147741000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-48] 2d 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-48] 2f 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kutphish_B_2147741001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.B"
        threat_id = "2147741001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-48] 2d 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-48] 2f 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kutphish_C_2147741002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.C"
        threat_id = "2147741002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kutphish_D_2147741003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.D"
        threat_id = "2147741003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kutphish_E_2147741234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.E"
        threat_id = "2147741234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 79 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 79 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kutphish_F_2147741235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutphish.F"
        threat_id = "2147741235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutphish"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 7a 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 7a 00 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

