rule Trojan_Win32_Yidcong_2147632193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yidcong"
        threat_id = "2147632193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yidcong"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mac=%s&os=%s&ver=%s&temp=%d&key=%d" ascii //weight: 1
        $x_1_2 = "web911899.w56.host-diy.net" ascii //weight: 1
        $x_1_3 = "theworld.exe" ascii //weight: 1
        $x_1_4 = "oreererrere.lnk" ascii //weight: 1
        $x_1_5 = "33=3=jvvr<11yyy058590eqo1" ascii //weight: 1
        $x_1_6 = "3637.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

