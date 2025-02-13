rule Trojan_Win32_NetShDisableFireWall_A_2147766115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetShDisableFireWall.A"
        threat_id = "2147766115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetShDisableFireWall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 73 00 68 00 [0-16] 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-16] 73 00 65 00 74 00 [0-16] 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 [0-16] 6f 00 66 00 66 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 73 00 68 00 [0-16] 61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 [0-16] 73 00 65 00 74 00 [0-16] 61 00 6c 00 6c 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 [0-16] 6f 00 66 00 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

