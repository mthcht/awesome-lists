rule TrojanProxy_Win32_Pirpi_A_2147626063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Pirpi.A"
        threat_id = "2147626063"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pirpi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GET class%d.cgi?talkid=%d" ascii //weight: 1
        $x_1_2 = "T:%d P:%s:%d H:%d" ascii //weight: 1
        $x_1_3 = "CONNECT %s:%d HTTP/1.1" ascii //weight: 1
        $x_1_4 = "GetFileSize1(%s) Error(%d)" ascii //weight: 1
        $x_1_5 = "CreateFile(%s) Error(%d)" ascii //weight: 1
        $x_1_6 = {0a 09 74 64 65 6c 61 79 0a 09 63 66 67 2e 0a 09 73 68 65 6c 6c 0a 09}  //weight: 1, accuracy: High
        $x_1_7 = {0a 09 67 65 74 66 2e 0a 09 70 6c 0a 09 70 6b 0a 09 75 6e 6c 6f 61 64 0a 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

