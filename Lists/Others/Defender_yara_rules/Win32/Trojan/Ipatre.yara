rule Trojan_Win32_Ipatre_RPT_2147824245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ipatre.RPT!MTB"
        threat_id = "2147824245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ipatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 52 8b 16 4f 8b 07 47 33 d0 46 ff 0c 24 8a c6 46 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

