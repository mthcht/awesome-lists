rule Trojan_Win32_Chepro_GK_2147894382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chepro.GK!MTB"
        threat_id = "2147894382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chepro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

