rule Trojan_Win32_PermissionGrpDisc_V_2147768882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PermissionGrpDisc.V"
        threat_id = "2147768882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PermissionGrpDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 6c 00 6f 00 63 00 61 00 6c 00 [0-2] 67 00 72 00 6f 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 [0-16] 6c 00 6f 00 63 00 61 00 6c 00 [0-2] 67 00 72 00 6f 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 20 00 [0-16] 6c 00 6f 00 63 00 61 00 6c 00 [0-2] 67 00 72 00 6f 00 75 00 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 31 00 20 00 [0-16] 6c 00 6f 00 63 00 61 00 6c 00 [0-2] 67 00 72 00 6f 00 75 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PermissionGrpDisc_VC_2147768883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PermissionGrpDisc.VC"
        threat_id = "2147768883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PermissionGrpDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-16] 67 00 65 00 74 00 2d 00 61 00 64 00 70 00 72 00 69 00 6e 00 63 00 69 00 70 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 6d 00 65 00 6d 00 62 00 65 00 72 00 73 00 68 00 69 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

