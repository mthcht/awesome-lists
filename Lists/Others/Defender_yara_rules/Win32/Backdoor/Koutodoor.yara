rule Backdoor_Win32_Koutodoor_C_2147631984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Koutodoor.C"
        threat_id = "2147631984"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Koutodoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 7d 0c 8b 45 08 32 1c 02}  //weight: 1, accuracy: High
        $x_1_2 = {83 bd 58 ff ff ff 02 75 09 83 bd 4c ff ff ff 05 73 56 8b 45 f0 83 f8 01 76 4e 83 4e 74 ff 03 c0 33 c9 a9 00 00 00 80 75 0b d1 6e 74 d1 e0 41 83 f9 20 7c ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

