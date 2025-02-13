rule Virus_Win32_Tank_A_2147606111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tank.gen!A"
        threat_id = "2147606111"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tank"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e8 00 00 00 00 81 2c 24 60 19 00 00 58 8d 90 e1 19 00 00 52 8d 90 87 1b 00 00 52 64 67 ff 36 00 00 64 67 89 26 00 00 33 c0 8b 55 04 66 81 3a 4d 5a 75 53 8b 4a 3c 8d 0c 0a 81 39 50 45 00 00 75 45}  //weight: 2, accuracy: High
        $x_1_2 = "X-Tank by Shadow" ascii //weight: 1
        $x_1_3 = "X-Tank Agent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

