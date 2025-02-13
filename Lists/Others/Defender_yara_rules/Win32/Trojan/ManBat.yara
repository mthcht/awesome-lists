rule Trojan_Win32_ManBat_AF_2147889318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ManBat.AF!MTB"
        threat_id = "2147889318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ManBat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a ef 4d 4a be 76 06 9e 5f c5 36 15 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71}  //weight: 1, accuracy: High
        $x_1_2 = "BLtJHwDDMHUBRIsOWuJU" ascii //weight: 1
        $x_1_3 = "MWIBANqOECByJiPZOQLU" ascii //weight: 1
        $x_1_4 = "ogqVHCVaKSoBpUFJCPTo" ascii //weight: 1
        $x_1_5 = "VOrJ185VOrJ200VOrJ200VOrJ188VOrJ185VOrJ204VOrJ185VOrJ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

