rule Trojan_Win32_ModifyFilePermission_AC_2147938348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ModifyFilePermission.AC"
        threat_id = "2147938348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ModifyFilePermission"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {69 00 63 00 61 00 63 00 6c 00 73 00 [0-10] 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 5c 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 70 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 73 00 5f 00 74 00 65 00 73 00 74 00 [0-8] 67 00 72 00 61 00 6e 00 74 00 20 00 75 00 73 00 65 00 72 00 73 00 3a 00 6d 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

