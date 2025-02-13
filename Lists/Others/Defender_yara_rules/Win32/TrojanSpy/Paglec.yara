rule TrojanSpy_Win32_Paglec_A_2147626689_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Paglec.A"
        threat_id = "2147626689"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Paglec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?mac=%s&ver=1.0" ascii //weight: 1
        $x_1_2 = "arplgm.cn/Count/Count.asp" ascii //weight: 1
        $x_1_3 = "d.txt|C:\\boot" ascii //weight: 1
        $x_1_4 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

