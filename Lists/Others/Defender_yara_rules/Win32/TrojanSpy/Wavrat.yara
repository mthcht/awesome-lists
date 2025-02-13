rule TrojanSpy_Win32_Wavrat_A_2147729235_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wavrat.A"
        threat_id = "2147729235"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wavrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%ws://%ws:%d%ws" wide //weight: 1
        $x_1_2 = "cdn.bitnami.com" wide //weight: 1
        $x_1_3 = ".cloudfront.net" wide //weight: 1
        $x_1_4 = "/atoms/auth_xXx/" ascii //weight: 1
        $x_1_5 = "username=%s" ascii //weight: 1
        $x_1_6 = "/atoms/%s/info" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

