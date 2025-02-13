rule Trojan_Win32_Enjectx_RPX_2147889438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Enjectx.RPX!MTB"
        threat_id = "2147889438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Enjectx"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4e 3c 03 cb 6a 00 ff b4 31 08 01 00 00 8b 84 31 0c 01 00 00 03 c6 50 8b 84 31 04 01 00 00 03 85 9c fb ff ff 50 ff b5 a8 fb ff ff ff 15 ?? ?? ?? ?? 8b 8d a0 fb ff ff 83 c3 28 0f b7 47 06 41 89 8d a0 fb ff ff 3b c8 7c b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

