rule Trojan_Win32_ConAtt_A_2147907156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConAtt.A"
        threat_id = "2147907156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConAtt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_1_2 = {2e 00 24 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 [0-32] 2b 00 27 00 65 00 78 00 27 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 24 00 28 00 5b 00 63 00 68 00 61 00 72 00 5d 00 28 00 [0-32] 2b 00 22 00 65 00 78 00 22 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ConAtt_B_2147910644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConAtt.B"
        threat_id = "2147910644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConAtt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-16] 5c 00 5c 00 [0-255] 64 00 61 00 76 00 77 00 77 00 77 00 72 00 6f 00 6f 00 74 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ConAtt_SE_2147933993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConAtt.SE"
        threat_id = "2147933993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConAtt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-32] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-32] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 10, accuracy: Low
        $x_1_2 = "get-content" wide //weight: 1
        $x_1_3 = "foreach-object" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ConAtt_HA_2147941337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConAtt.HA!MTB"
        threat_id = "2147941337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConAtt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 20 00 72 00 75 00 6e 00 6c 00 65 00 67 00 61 00 63 00 79 00 63 00 70 00 6c 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 [0-8] 20 00 [0-32] 22 01 01 02 20 2c [0-32] 20 00 [0-2] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 [0-70] 2e 00 [0-10] 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

