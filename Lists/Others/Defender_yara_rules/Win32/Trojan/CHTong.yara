rule Trojan_Win32_CHTong_2147641461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CHTong"
        threat_id = "2147641461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CHTong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\Autosystem.vbs" wide //weight: 10
        $x_10_2 = "http://baidu.wxbjy.info" wide //weight: 10
        $x_10_3 = "WSHShell.Run" wide //weight: 10
        $x_5_4 = "\\tencent\\qzone.exe" wide //weight: 5
        $x_5_5 = {5c 00 74 00 65 00 6e 00 63 00 65 00 6e 00 74 00 5c 00 [0-4] 2e 00 62 00 61 00 74 00}  //weight: 5, accuracy: Low
        $x_5_6 = "\\tencent\\smm.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

