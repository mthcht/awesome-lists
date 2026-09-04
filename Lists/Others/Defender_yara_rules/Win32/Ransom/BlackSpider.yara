rule Ransom_Win32_BlackSpider_XV_2147977555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSpider.XV!MTB"
        threat_id = "2147977555"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSpider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b fe 8b c1 24 01 f6 d8 1a c0 41 24 69 04 6b 30 07 47 83 f9 30 72}  //weight: 3, accuracy: High
        $x_2_2 = ".bl4ck" ascii //weight: 2
        $x_2_3 = "R3ADM3.txt" ascii //weight: 2
        $x_2_4 = "sp1d3r" ascii //weight: 2
        $x_2_5 = "DisableAntiVirus" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

