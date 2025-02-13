rule Backdoor_Win32_Zuza_2147633108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zuza"
        threat_id = "2147633108"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zuza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST /index.asp HTTP/1.1" ascii //weight: 1
        $x_1_2 = "sens64.dll" ascii //weight: 1
        $x_1_3 = "mscmos.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

