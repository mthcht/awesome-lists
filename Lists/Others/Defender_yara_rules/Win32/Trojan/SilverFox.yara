rule Trojan_Win32_SilverFox_MK_2147969898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SilverFox.MK!MTB"
        threat_id = "2147969898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b 45 e8 8d 75 e0 56 52 50 8b 08 ff 51 1c c7 45 fc ff ff ff ff 83 cf ff 8b 75 dc 89 45 e4 85 f6}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

