rule Trojan_Win32_Uztuby_KAA_2147901603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uztuby.KAA!MTB"
        threat_id = "2147901603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uztuby"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 f2 02 89 d0 01 c2 42 89 35 ?? ?? ?? ?? 42 b8 ?? ?? ?? ?? 89 d0 31 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

