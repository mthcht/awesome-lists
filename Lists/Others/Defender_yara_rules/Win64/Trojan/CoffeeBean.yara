rule Trojan_Win64_CoffeeBean_A_2147930498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoffeeBean.A!dha"
        threat_id = "2147930498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoffeeBean"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 69 69 78 20 51 12 81 80 17 12 34 10 67 11 14 16 13 33 21 39 49 45 13 85 10 87 22 96 10 64 46}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

