rule Trojan_Win32_Rhadamanthus_MR_2147949737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamanthus.MR!MTB"
        threat_id = "2147949737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 40 20 20 20 20 20 20 20 20 14 c9 03 00 00 e0 05 00 00 36 01}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 c0 20 20 20 20 20 20 20 20 68 40 ?? ?? ?? b0 09 00 00 38 ?? ?? ?? 36 04}  //weight: 5, accuracy: Low
        $x_5_3 = {40 00 00 40 2e 69 64 61 74 61 ?? ?? ?? 10 ?? ?? ?? ?? 0a 00 00 02 ?? ?? ?? 6e 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

