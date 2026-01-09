rule Trojan_Win32_Amatera_AMT_2147960835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amatera.AMT!MTB"
        threat_id = "2147960835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amatera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 8d 4d db e8 ?? ?? ?? ?? 89 45 d4 83 7d d4 00 75 16 68 d0 07 00 00 ff 15 ?? ?? ?? ?? 8b 4d fc 83 c1 01 89 4d fc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

