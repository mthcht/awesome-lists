rule Worm_Win32_Baluk_2147607421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Baluk"
        threat_id = "2147607421"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Baluk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 00 3a 00 5c 00 b9 00 c6 00 c6 00 cb 00 c3 00 c6 00 be 00 2e 00 ba 00 bd 00 be 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 ec 00 f1 00 e9 00 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 3d b3 00 7c 1c 66 3d fd 00 7f 16 8b 55 d8 52 ff d3 66 2d 83 00 0f 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

