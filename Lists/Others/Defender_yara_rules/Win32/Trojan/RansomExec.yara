rule Trojan_Win32_RansomExec_SA_2147957301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RansomExec.SA"
        threat_id = "2147957301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RansomExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 [0-48] 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 [0-16] 32 00 3e 00 6e 00 75 00 6c 00 [0-16] 65 00 78 00 69 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 74 00 61 00 72 00 74 00 20 00 2f 00 62 00 20 00 63 00 6d 00 64 00 20 00 2f 00 63 00 [0-48] 25 00 70 00 75 00 62 00 6c 00 69 00 63 00 25 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 [0-16] 32 00 3e 00 6e 00 75 00 6c 00 [0-16] 65 00 78 00 69 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

