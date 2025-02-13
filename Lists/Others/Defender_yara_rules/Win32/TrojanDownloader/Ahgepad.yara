rule TrojanDownloader_Win32_Ahgepad_A_2147616241_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ahgepad.A"
        threat_id = "2147616241"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ahgepad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "58"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "KeServiceDescriptorTable" ascii //weight: 10
        $x_10_2 = "www.345dh.cn" ascii //weight: 10
        $x_10_3 = "www.hahapage.cn" ascii //weight: 10
        $x_10_4 = "127.0.0.2 localhost" ascii //weight: 10
        $x_10_5 = "\\Device\\KappaAvb" wide //weight: 10
        $x_1_6 = "DllRegisterServer" wide //weight: 1
        $x_1_7 = "etc\\hosts" wide //weight: 1
        $x_1_8 = "Start Page" wide //weight: 1
        $x_1_9 = "\\Software\\Microsoft\\Internet Explorer\\Main" wide //weight: 1
        $x_1_10 = "zhaodao123.com" wide //weight: 1
        $x_1_11 = "ZHAOY.NET" wide //weight: 1
        $x_1_12 = "baidu.com" wide //weight: 1
        $x_1_13 = "hao123.com" wide //weight: 1
        $x_1_14 = "345dh.cn?tg=%d" wide //weight: 1
        $x_1_15 = "hahapage.cn?tg=%d" wide //weight: 1
        $x_1_16 = "google.cn/webhp?client=pub-0936066011120520&prog=aff&ie=gb2312&oe=gb2312&hl=zh-cn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

