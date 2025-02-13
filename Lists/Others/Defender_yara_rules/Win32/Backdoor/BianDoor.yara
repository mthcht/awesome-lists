rule Backdoor_Win32_BianDoor_C_2147904756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/BianDoor.C"
        threat_id = "2147904756"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "BianDoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 61 2e 6f 75 74 2e 65 78 65 00 45 6e 74 72 79 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 ?? 6f 72 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

