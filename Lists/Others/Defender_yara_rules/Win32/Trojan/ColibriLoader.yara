rule Trojan_Win32_ColibriLoader_FA_2147895878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ColibriLoader.FA!MTB"
        threat_id = "2147895878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ColibriLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f be c0 33 c3 69 d8 93 01 00 01 41 8a 01 84 c0 75 ee}  //weight: 3, accuracy: High
        $x_2_2 = {30 04 32 42 3b d7 72 ed 8b 7d f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

