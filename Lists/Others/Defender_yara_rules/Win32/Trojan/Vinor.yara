rule Trojan_Win32_Vinor_A_2147696893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vinor.A"
        threat_id = "2147696893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vinor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "modGetHProcExe" ascii //weight: 3
        $x_3_2 = "hVrTraychk" ascii //weight: 3
        $x_1_3 = "WinHttp.WinHttpRequest.5.1" wide //weight: 1
        $x_1_4 = "avp.exe" wide //weight: 1
        $x_1_5 = "blog.naver.com/PostView.nhn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

