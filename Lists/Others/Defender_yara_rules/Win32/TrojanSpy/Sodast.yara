rule TrojanSpy_Win32_Sodast_A_2147631756_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Sodast.A"
        threat_id = "2147631756"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Sodast"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X-Rand: " ascii //weight: 1
        $x_1_2 = "!cmd.exe /C c:\\" ascii //weight: 1
        $x_1_3 = "FCIAddFile" ascii //weight: 1
        $x_1_4 = "POST %s HTTP/1.0" ascii //weight: 1
        $x_1_5 = "fox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

