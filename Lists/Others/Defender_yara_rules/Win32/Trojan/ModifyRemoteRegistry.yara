rule Trojan_Win32_ModifyRemoteRegistry_A_2147920801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModifyRemoteRegistry.A"
        threat_id = "2147920801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModifyRemoteRegistry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {72 00 65 00 67 00 [0-8] 20 00 61 00 64 00 64 00 20 00}  //weight: 6, accuracy: Low
        $x_1_2 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 73 00 65 00 74 00 5c 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 72 00 65 00 6d 00 6f 00 74 00 65 00 20 00 61 00 73 00 73 00 69 00 73 00 74 00 61 00 6e 00 63 00 65 00 [0-2] 20 00 2f 00 76 00 20 00 66 00 61 00 6c 00 6c 00 6f 00 77 00 74 00 6f 00 67 00 65 00 74 00 68 00 65 00 6c 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

