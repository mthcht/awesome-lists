rule Trojan_Win32_Radthief_GVA_2147935569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Radthief.GVA!MTB"
        threat_id = "2147935569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Radthief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 cc 30 04 37 46 8b 45 d8 8b 7d d4 83 45 c4 11 89 45 bc 2b c7 89 75 b4 3b f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

