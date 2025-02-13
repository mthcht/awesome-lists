rule Trojan_Win32_Zenapk_CCCI_2147892626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapk.CCCI!MTB"
        threat_id = "2147892626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "meatbXNdivided" ascii //weight: 1
        $x_1_2 = "Bflywingedhisa" ascii //weight: 1
        $x_1_3 = "VfishgivenfpHmoved" ascii //weight: 1
        $x_1_4 = "aboveStherex" ascii //weight: 1
        $x_1_5 = "sayingmeatitself" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

