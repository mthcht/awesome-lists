rule Trojan_Win32_ZeusKlog_A_2147730307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZeusKlog.A!MTB"
        threat_id = "2147730307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZeusKlog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keylog.exe" ascii //weight: 1
        $x_1_2 = "KLog\\screen\\%04d.%02d.%02d.%02d.%02d.%02d.%02d_%05d" wide //weight: 1
        $x_1_3 = "KLog\\file\\%04d.%02d.%02d.%02d.%02d.%02d.%02d_%05d" wide //weight: 1
        $x_1_4 = "%ws\\KScn_%x.jpeg" wide //weight: 1
        $x_1_5 = "[Make screenshot: KScn_%x]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

