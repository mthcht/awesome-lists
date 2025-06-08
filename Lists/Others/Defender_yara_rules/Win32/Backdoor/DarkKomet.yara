rule Backdoor_Win32_DarkKomet_PA_2147759100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/DarkKomet.PA!MTB"
        threat_id = "2147759100"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkKomet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Go build ID: \"S8b0Bu4sIueomyIgwvW9/8tDFmeLjKNy2aRHATRZ5/fnHkdeFA7ysHAYaUmAz9/kY99_VXk9q6ANLJREYo2\"" ascii //weight: 5
        $x_1_2 = "Encrypt" ascii //weight: 1
        $x_1_3 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
        $x_1_4 = "m=+Inf, n -Inf.bat.cmd.com.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

