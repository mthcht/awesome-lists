rule Virus_Win32_Partriot_B_2147601414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Partriot.B"
        threat_id = "2147601414"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Partriot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MapViewOfFile" ascii //weight: 10
        $x_1_2 = "A:\\Win32.Friendly.htm" ascii //weight: 1
        $x_1_3 = "::::: Win32.Friendly has you :::::" ascii //weight: 1
        $x_10_4 = {55 8b ec 8b 45 0c 8b 40 2c 25 df df df df 3d 44 52 57 45 74 37 3d 53 50 49 44 74 30 25 ff ff ff 00 3d 4b 41 56 00 74 24 ff 75 0c ff 75 08 e8 1d 00 00 00 85 c0 75 15 8b 55 08 80 3a 41 74 0d 50 68 20 4e 00 00 ff 93 ab 14 00 00 58 c9 c2 08 00}  //weight: 10, accuracy: High
        $x_10_5 = {33 c9 e8 3f 02 00 00 85 c0 0f 84 03 02 00 00 89 45 f8 e8 3f 02 00 00 85 c0 0f 84 ea 01 00 00 89 45 f4 66 81 38 4d 5a 0f 85 cc 01 00 00 66 83 78 18 40 0f 85 c1 01 00 00 8b 40 3c 89 45 e4 03 45 f4 81 38 50 45 00 00 0f 85 ac 01 00 00 80 78 ff 2a 0f 84 99 01 00 00 8b f8 0f b7 47 06 48 6b c0 28}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

