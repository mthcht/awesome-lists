rule SoftwareBundler_Win32_NetPumper_15103_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/NetPumper"
        threat_id = "15103"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "NetPumper"
        severity = "25"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 00 4e 65 74 50 75 6d 70 65 72 2f 30 2e 30 00 50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 00 25 73 3a 25 64 00 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 0d 0a 00 2a 2f 2a 00 25 73}  //weight: 5, accuracy: High
        $x_3_2 = {00 4e 65 74 50 75 6d 70 65 72 2e 65 78 65 00 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 66 69 6c 65}  //weight: 3, accuracy: High
        $x_2_3 = ", NetPumper v" ascii //weight: 2
        $x_2_4 = "NetPumper.AddUrl" ascii //weight: 2
        $x_2_5 = "BUILD\\ANTI-LEECH\\NetPumper\\NetPumper" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

