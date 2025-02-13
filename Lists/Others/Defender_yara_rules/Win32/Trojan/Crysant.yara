rule Trojan_Win32_Crysant_RPS_2147830182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysant.RPS!MTB"
        threat_id = "2147830182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 40 00 04 00 00 00 04 00 00 00 01 c0 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

