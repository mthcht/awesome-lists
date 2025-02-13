rule TrojanDropper_Win32_Stration_SQ_2147607963_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Stration.SQ"
        threat_id = "2147607963"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "GET %s HTTP/1.1" ascii //weight: 10
        $x_10_2 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 10
        $x_10_3 = "Accept-Encoding: gzip, deflate" ascii //weight: 10
        $x_1_4 = {74 72 79 2d 61 6e 79 74 68 69 6e 67 2d 65 6c 73 65 2e 63 6f 6d 2f [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {6c 6f 63 61 6c 68 6f 73 74 2d 32 2e 63 6f 6d 2f [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {72 78 2d 66 72 6f 6d 2d 77 61 72 65 68 6f 75 73 65 33 2e 63 6f 6d 2f [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

