rule Trojan_Win32_Morkus_GNI_2147894008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Morkus.GNI!MTB"
        threat_id = "2147894008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Morkus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 20 41 13 34 72 50 07 bc ?? ?? ?? ?? 17 3c f3 85 34 58 0b 7e 12 80 78 d6 0b d3 a3 ?? ?? ?? ?? 2b f4 0f fd d4 0a 04 f2 2c 37 e7 7b 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

