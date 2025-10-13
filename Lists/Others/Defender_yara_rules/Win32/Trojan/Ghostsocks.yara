rule Trojan_Win32_Ghostsocks_AGS_2147954916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ghostsocks.AGS!MTB"
        threat_id = "2147954916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ghostsocks"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 3c b2 0f b6 3f 89 3c b0 8d 6e 01 39 cd 7d ?? 89 ee c1 e5 02 39 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

