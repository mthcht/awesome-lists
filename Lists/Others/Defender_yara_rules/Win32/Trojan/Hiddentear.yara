rule Trojan_Win32_Hiddentear_Z_2147938581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hiddentear.Z!MTB"
        threat_id = "2147938581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hiddentear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 01 12 80 a1 12 81 0d 05 00 00 12 81 11 07 20 02 01 0e 12 81 11 06 00 01 12 81 15 0e 17 07 0d 08 08 08 1d 05 0a 0a 08 12 80 a9 12 80 ad 11 2c 02 02 12 80 b1 0a 20 03 01 0e 11 81 19 11 81 1d 04 20 01 01 0a 03 20 00 0a 09 20 02 12 81 25 1d 05 1d 05 0c 20 03 01 12 81 0d 12 81 25 11 81 29 07 20 03 08 1d 05 08 08 07 20 03 01 1d 05 08 08 1b 07 0f 08 08 08 1d 05 0a 0a 08 12 80 a9 12 80 ad 11 2c 02 02 12 80 b1 02 12 80 b1 13 07 0a 1d 05 1d 03 08 1d 05 12 80 b5 1d 05 1d 05 08 08 08 04 20 00 1d 03 04 20 01 08 08 04 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {6f 3d 00 00 0a 13 3f 2b 4e 12 3f 28 3e 00 00 0a 13 40 1f 6e 0d 11 40 28 3f 00 00 0a 13 41 11 41 2c 31 1f 6f 0d 11 40 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

