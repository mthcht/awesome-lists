rule TrojanProxy_Win32_Mediana_2147696873_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Mediana"
        threat_id = "2147696873"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Mediana"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "This Page is Establishing..." ascii //weight: 4
        $x_4_2 = "POST http://%s:%d/index.cgi?%s&%s HTTP/1.0" ascii //weight: 4
        $x_2_3 = "CRSERVER_MUTEX_ONCE" ascii //weight: 2
        $x_2_4 = "x-wav/y-img" ascii //weight: 2
        $x_2_5 = "\\msextlog.dll" ascii //weight: 2
        $x_2_6 = {3c 2e 75 15 80 7c 31 01 45 75 0e 80 7c 31 02 58 75 07 80 7c 31 03 45 74 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

