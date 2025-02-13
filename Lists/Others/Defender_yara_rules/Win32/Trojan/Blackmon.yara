rule Trojan_Win32_Blackmon_A_2147681475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blackmon.A"
        threat_id = "2147681475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blackmon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "awekhsg" ascii //weight: 1
        $x_1_2 = "Sandboxia.ini" ascii //weight: 1
        $x_1_3 = "596257DD93F30956A057A29F3A99" ascii //weight: 1
        $x_1_4 = "blackmoon" ascii //weight: 1
        $x_1_5 = "/Telxclsjcgzh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

