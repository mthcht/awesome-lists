rule Trojan_Win32_Eternal_RPH_2147840899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eternal.RPH!MTB"
        threat_id = "2147840899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eternal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baum1810" ascii //weight: 1
        $x_1_2 = ":%AKkli%:" ascii //weight: 1
        $x_1_3 = ":%LhVatFMBX%:" ascii //weight: 1
        $x_1_4 = ":%AHgTQ%:" ascii //weight: 1
        $x_1_5 = ":%QkKwyILk%:" ascii //weight: 1
        $x_1_6 = ":%UDYUDZJe%:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eternal_RPI_2147840900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eternal.RPI!MTB"
        threat_id = "2147840900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eternal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baum1810" ascii //weight: 1
        $x_1_2 = ":%xjFNBrQwM%:" ascii //weight: 1
        $x_1_3 = ":%xelOzSY%:" ascii //weight: 1
        $x_1_4 = ":%Lolv%:" ascii //weight: 1
        $x_1_5 = ":%HSULIxVLl%:" ascii //weight: 1
        $x_1_6 = ":%JZdAnHQXjf%:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

