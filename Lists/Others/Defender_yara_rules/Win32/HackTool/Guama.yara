rule HackTool_Win32_Guama_A_2147627363_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Guama.A"
        threat_id = "2147627363"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Guama"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QQ:123456" wide //weight: 1
        $x_1_2 = "hacker = \"E:\\asp\\hostIng\\wwwroot\\zbdq_net\\htdocS\\Inc" wide //weight: 1
        $x_1_3 = "Call GetAll(hacker)" wide //weight: 1
        $x_1_4 = "guma = \"<iframe src='http://www.hacker.com.cn'></iframe>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

