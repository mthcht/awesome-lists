rule PWS_Win32_Seratin_A_2147623449_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Seratin.A"
        threat_id = "2147623449"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Seratin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\winaccestor.dat" ascii //weight: 1
        $x_1_2 = "/?ok=1&app_id=" ascii //weight: 1
        $x_1_3 = "CLSID\\{A8981DB9-B2B3-47D7-A890-9C9D9F4C5552}" ascii //weight: 1
        $x_1_4 = "/?mode=update" ascii //weight: 1
        $x_1_5 = "Accept-Language:ru" ascii //weight: 1
        $x_1_6 = "ad-config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

