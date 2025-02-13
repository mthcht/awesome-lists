rule Worm_Win32_Looked_2147598082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Looked"
        threat_id = "2147598082"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Looked"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "180"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 61 76 4d 6f 6e 43 6c 61 73 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {5a 41 46 72 61 6d 65 57 6e 64 00}  //weight: 2, accuracy: High
        $x_2_3 = "shellexecute=" ascii //weight: 2
        $x_4_4 = {00 3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 4, accuracy: High
        $x_100_5 = "<iframe src=http:" ascii //weight: 100
        $x_6_6 = {5c 69 70 63 24 00}  //weight: 6, accuracy: High
        $x_6_7 = {5c 61 64 6d 69 6e 24 00}  //weight: 6, accuracy: High
        $x_30_8 = "WNetCancelConnection2A" ascii //weight: 30
        $x_30_9 = "WNetAddConnection2A" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_30_*) and 2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

