rule Backdoor_Win32_Nupic_A_2147640589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nupic.A"
        threat_id = "2147640589"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nupic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "accesopd" ascii //weight: 10
        $x_10_2 = "UNIQUAWI*" ascii //weight: 10
        $x_1_3 = "POST http://%s:%d/net/B%s/serinfo HTTP/1.1" ascii //weight: 1
        $x_1_4 = "nNewsNn" ascii //weight: 1
        $x_1_5 = "%s http://about:blank" ascii //weight: 1
        $x_1_6 = "http\\shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

