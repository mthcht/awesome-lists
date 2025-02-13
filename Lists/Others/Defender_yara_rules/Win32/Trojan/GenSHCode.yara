rule Trojan_Win32_GenSHCode_GMP_2147892327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GenSHCode.GMP!MTB"
        threat_id = "2147892327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GenSHCode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 ac 68 95 08 54 c9 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 c7 01 88 47 ff 51 83 c4 04 ?? ?? ?? ?? c7 44 24 ?? 11 88 a6 44 4a 83 c2 02 68 17 4d b1 44 83 c4 04 49 85 c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

