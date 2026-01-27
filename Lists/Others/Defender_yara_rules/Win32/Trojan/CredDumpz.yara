rule Trojan_Win32_CredDumpz_DA_2147961767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredDumpz.DA!MTB"
        threat_id = "2147961767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredDumpz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 00 65 00 67 00 [0-6] 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00 20 00 [0-60] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 68 00 69 00 76 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 65 00 67 00 [0-6] 73 00 61 00 76 00 65 00 20 00 48 00 4b 00 4c 00 4d 00 5c 00 53 00 41 00 4d 00 20 00 [0-60] 73 00 61 00 6d 00 2e 00 68 00 69 00 76 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

