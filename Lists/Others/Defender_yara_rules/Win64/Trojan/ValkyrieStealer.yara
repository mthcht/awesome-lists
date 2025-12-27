rule Trojan_Win64_ValkyrieStealer_GDX_2147958714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValkyrieStealer.GDX!MTB"
        threat_id = "2147958714"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValkyrieStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c e9 cb 1f c7 45 ?? 97 16 af 43 c7 45 ?? 91 40 28 97 c7 45 ?? c7 c6 97 67 c7 85 ?? ?? ?? ?? 07 b8 c2 c9 c7 85 ?? ?? ?? ?? 31 77 34 4f c7 85 ?? ?? ?? ?? 81 b7 44 ff c7 85 ?? ?? ?? ?? 77 79 52 2b}  //weight: 10, accuracy: Low
        $x_1_2 = "Login Data" ascii //weight: 1
        $x_1_3 = "passwords" ascii //weight: 1
        $x_1_4 = "Web Data" ascii //weight: 1
        $x_1_5 = "cookies" ascii //weight: 1
        $x_1_6 = "ReadCookie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

