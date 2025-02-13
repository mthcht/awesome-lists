rule Trojan_Win32_Siggen_GR_2147814963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Siggen.GR!MTB"
        threat_id = "2147814963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Siggen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 43 18 ff ff ff ff c7 43 28 ff ff ff ff c7 43 30 ff ff ff ff c7 43 48 28 81 40 00 c7 43 4c f0 72 40 00 8d b5 56 ff ff ff 8d 85 75 ff ff ff b1 01 eb 03}  //weight: 10, accuracy: High
        $x_10_2 = {88 45 ef 0f be 45 ef 89 45 f4 8b 45 10 31 45 f4 8b 45 f4 88 45 ef 8a 55 ef 8b 45 e4 88 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

