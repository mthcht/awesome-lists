rule Ransom_Win32_LockedFile_G_2147757237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LockedFile.G!MSR"
        threat_id = "2147757237"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LockedFile"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 13 85 d2 74 1a c7 03 00 00 00 00 8b 4a f8 49 7c 0e f0 ff 4a f8 75 08 8d 42 f4 e8 be cf ff ff 83 c3 04 4e 75 da}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 94 1c 85 c9 74 10 03 41 fc a9 00 00 00 c0 75 73 39 cf 75 02 31 ff 4a 75 e5}  //weight: 1, accuracy: High
        $x_1_3 = {73 6f 66 74 5f 34 5f 35 5f 02 00 5f 61 64 76 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

