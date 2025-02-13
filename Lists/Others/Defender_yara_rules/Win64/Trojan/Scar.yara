rule Trojan_Win64_Scar_GMK_2147892258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scar.GMK!MTB"
        threat_id = "2147892258"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 89 f1 4c 89 4c 24 58 e8 ?? ?? ?? ?? 31 d2 41 ba 3e 00 00 00 44 89 f9 89 c0 41 ff c7 4c 8b 4c 24 58 49 f7 f2 44 39 7c 24 48 66 0f be 44 15 00 66 41 89 04 4c}  //weight: 10, accuracy: Low
        $x_1_2 = "Global\\M%llu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Scar_NA_2147928373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Scar.NA!MTB"
        threat_id = "2147928373"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 bf 32 a2 df 2d 99 2b 00 00 48 3b c7 74 0c 48 f7 d0 48 89 05 38 19 00 00 eb 76 48 8d 4c 24 30 ff 15 eb d8 ff ff 48 8b 5c 24 30 ff 15 e8 d8 ff ff 44 8b d8 49 33 db ff 15 e4 d8 ff ff 44 8b d8 49 33 db ff 15 e0 d8 ff ff 48 8d 4c 24 38 44 8b d8 49 33 db ff 15 d7 d8 ff ff 4c 8b 5c 24 38 4c 33 db 48 b8 ff}  //weight: 3, accuracy: High
        $x_1_2 = "Internet Backgammon" ascii //weight: 1
        $x_1_3 = "mbckg_zm_***" wide //weight: 1
        $x_1_4 = "qwx0X" ascii //weight: 1
        $x_1_5 = "QuasiChat" wide //weight: 1
        $x_1_6 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

