rule Trojan_Win32_Fexacer_A_2147626852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fexacer.A"
        threat_id = "2147626852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fexacer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{BC5B92BE-EA14-4e0a-95A3-87F80C02B987}_" ascii //weight: 1
        $x_1_2 = ".118fox.com.cn/" ascii //weight: 1
        $x_1_3 = "&pop_rule_id=" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\MacAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

