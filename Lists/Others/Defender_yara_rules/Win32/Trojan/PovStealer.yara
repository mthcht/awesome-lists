rule Trojan_Win32_PovStealer_AD_2147892747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PovStealer.AD!MTB"
        threat_id = "2147892747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PovStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 4d c7 0f b6 55 c7 c1 fa 06 0f b6 45 c7 c1 e0 02 0b d0 88 55 c7 8b 4d c8 8a 55 c7 88 54 0d d8 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

