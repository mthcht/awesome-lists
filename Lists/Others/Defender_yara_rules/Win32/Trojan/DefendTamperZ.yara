rule Trojan_Win32_DefendTamperZ_A_2147957646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DefendTamperZ.A!MTB"
        threat_id = "2147957646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DefendTamperZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 20 00 2f 00 64 00 [0-16] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 70 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

