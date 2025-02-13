rule Trojan_Win32_Zapper_A_2147728135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zapper.A"
        threat_id = "2147728135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://checkandswitch.com/afile/7.exe" ascii //weight: 1
        $x_1_2 = "https://adfiles.ru/main/tiger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

