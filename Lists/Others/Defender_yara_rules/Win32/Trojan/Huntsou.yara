rule Trojan_Win32_Huntsou_18137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Huntsou"
        threat_id = "18137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Huntsou"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Software\\microsoft\\Windows\\CurrentVersion\\Ext\\Settings\\{00C104F7-0F5C-470C-ABCF-A5B2E70752F1}" ascii //weight: 3
        $x_3_2 = {77 72 69 73 69 6e 67 00 [0-10] 2e 64 6c 6c 00 00 72 65 67 73 76 72 33 32 20 2f 73 20 25 73 00}  //weight: 3, accuracy: Low
        $x_2_3 = "http://www5.baidu.com/baidu?" ascii //weight: 2
        $x_3_4 = "cook5**rrr)]\\d_p)^jh*n:" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Huntsou_18137_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Huntsou"
        threat_id = "18137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Huntsou"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "seek.3721.com" ascii //weight: 2
        $x_2_2 = "ForceRemove {00C104F7-0F5C-470C-ABCF-A5B2E70752F1} = s 'LpkHlpr Class'" ascii //weight: 2
        $x_2_3 = "'TypeLib' = s '{DB7F4BCA-E094-44C9-B1F8-B5AC0BC1A972}'" ascii //weight: 2
        $x_2_4 = "IBaiduHlpr InterfaceWW" ascii //weight: 2
        $x_2_5 = "MS lpk Module" wide //weight: 2
        $x_3_6 = "cook5**rrr)]\\d_p)^jh*n:" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Huntsou_18137_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Huntsou"
        threat_id = "18137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Huntsou"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "46"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://www.baidu.com/s?" ascii //weight: 1
        $x_1_2 = "http://www.baidu.com/baidu?" ascii //weight: 1
        $x_1_3 = "http://www.baidu.cn/s?" ascii //weight: 1
        $x_1_4 = "http://www.baidu.cn/baidu?" ascii //weight: 1
        $x_1_5 = "http://www5.baidu.com/s?" ascii //weight: 1
        $x_2_6 = "http://www5.baidu.com/baidu?" ascii //weight: 2
        $x_2_7 = "cns.3721.com" ascii //weight: 2
        $x_2_8 = "seek.3721.com" ascii //weight: 2
        $x_10_9 = "url_new2 %s" ascii //weight: 10
        $x_10_10 = "cook5**rrr)]\\d_p)^i*" ascii //weight: 10
        $x_10_11 = "cook5**]\\d_p)^" ascii //weight: 10
        $x_20_12 = "cook5**rrr)]\\d_p)^jh*n:" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_2_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

