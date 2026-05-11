rule Trojan_Win32_Bypassuac_MKR_2147968957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bypassuac.MKR!MTB"
        threat_id = "2147968957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bypassuac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 ff d7 8b f0 85 f6 ?? ?? 8d 44 24 ?? 50 6a ?? 6a ?? 56 ff d3 c7 44 24 ?? ?? ?? ?? ?? 32 c9 8b 44 24 ?? 89 06 8d 44 24 ?? 50 88 4e 04 ff 74 24 ?? 6a ?? 56 ff d3}  //weight: 5, accuracy: Low
        $x_3_2 = {50 ff d7 8b f0 85 f6 ?? ?? 8d 44 24 ?? 50 6a ?? 6a ?? 56 ff d3 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 89 06 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 89 46 ?? 8d 44 24 ?? 50 ff 74 24 ?? 6a ?? 56 ff d3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

