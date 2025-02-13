rule Worm_Win32_Wangy_C_2147653345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wangy.gen!C"
        threat_id = "2147653345"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wangy"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.01sos.com" ascii //weight: 1
        $x_1_2 = "hy2010a" ascii //weight: 1
        $x_1_3 = "DeleteMe.bat" ascii //weight: 1
        $x_10_4 = {65 78 69 73 74 20 22 00 22 20 67 6f 74 6f 20 74 72 79 00 64 65 6c 20 25 30 00 00 69 6e 74 66 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

