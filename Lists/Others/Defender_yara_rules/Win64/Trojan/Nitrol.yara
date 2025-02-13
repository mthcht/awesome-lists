rule Trojan_Win64_Nitrol_YAA_2147922586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nitrol.YAA!MTB"
        threat_id = "2147922586"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nitrol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f 1f 44 00 00 48 8b 05 ?? ?? ?? ?? 31 14 03 48 83 c3 04 8b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15}  //weight: 10, accuracy: Low
        $x_4_2 = "PMjUMWFak" ascii //weight: 4
        $x_4_3 = "nJlQwxpjRBQX" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

