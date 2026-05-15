rule Ransom_Win64_LockScreen_PGBD_2147969402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockScreen.PGBD!MTB"
        threat_id = "2147969402"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockScreen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4f 00 6f 00 6f 00 70 00 73 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 72 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 21 00 20 00 54 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 20 00 66 00 6f 00 72 00 20 00 63 00 6f 00 6e 00 74 00 61 00 63 00 74 00 3a 00 [0-32] 3e 00 69 00 6e 00 66 00 6f 00 2d 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 74 00 78 00 74 00 20 00 26 00 20 00 61 00 74 00 74 00 72 00 69 00 62 00 20 00 2d 00 68 00 20 00 2b 00 73 00 20 00 2b 00 72 00 20 00 69 00 6e 00 66 00 6f 00 2d 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 2e 00 74 00 78 00 74 00}  //weight: 4, accuracy: Low
        $x_2_2 = "Windows blocked!" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

