rule Trojan_Win32_Mbot_2147639513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mbot"
        threat_id = "2147639513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msg=%s&%s" ascii //weight: 1
        $x_1_2 = "POST /start?rcs=1&spid= HTTP/1.1" ascii //weight: 1
        $x_1_3 = "%s\\wlmsn.exe" ascii //weight: 1
        $x_1_4 = "echo %s > %%temp%%\\volumeinfo.dat" ascii //weight: 1
        $x_1_5 = "recaptchaRequired" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

