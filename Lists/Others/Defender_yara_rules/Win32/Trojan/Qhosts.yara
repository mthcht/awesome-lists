rule Trojan_Win32_Qhosts_AY_2147663912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qhosts.AY"
        threat_id = "2147663912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qhosts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 70 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_2 = ":45612/stat/tuk/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

