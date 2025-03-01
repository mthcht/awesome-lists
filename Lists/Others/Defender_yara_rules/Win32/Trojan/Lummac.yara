rule Trojan_Win32_lummac_PLJH_2147929155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/lummac.PLJH!MTB"
        threat_id = "2147929155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 d9 01 ce 46 0f b6 84 34 ?? ?? ?? ?? 8b 0c 24 00 c1 89 0c 24 0f b6 c9 0f b6 94 0c ?? ?? ?? ?? 88 94 34 ?? ?? ?? ?? 88 84 0c ?? ?? ?? ?? 02 84 34 ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 30 04 19 43 3b 9c 24 ?? ?? ?? ?? 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

