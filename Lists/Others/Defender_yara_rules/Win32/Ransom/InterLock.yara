rule Ransom_Win32_InterLock_A_2147968020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/InterLock.A"
        threat_id = "2147968020"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "InterLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 74 00 6d 00 70 00 [0-255] 2e 00 77 00 61 00 73 00 64 00 [0-48] 72 00 75 00 6e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

