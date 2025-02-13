rule Ransom_Win32_Blocker_NN_2147743863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blocker.NN!MTB"
        threat_id = "2147743863"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 37 03 c2 8b 55 ?? 81 c2 ?? ?? 00 00 8b ca 33 d2 f7 f1 8a 04 17 88 45 ?? 8d 45 ?? 8b 55 ?? 8b 4d ?? 8a 54 0a ?? 8a 4d ?? 32 d1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 8b c3 2d b7 a0 0b 00 50 6a 00 8b c3 2d b9 a0 0b 00 50 81 c3 46 5f f4 7f 53 8b 45 ?? e8 c4 60 fb ff 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Blocker_MA_2147840325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Blocker.MA!MTB"
        threat_id = "2147840325"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Vel9AQAAX4vv6LQAAACL/VcGD6AHJqEw" ascii //weight: 5
        $x_5_2 = "AOtFUVaLdTyLdDV4A/VWi3YgA/UzyUlB" ascii //weight: 5
        $x_5_3 = "AFFVA81R6AEAAADDi0QkDFaLdCQMwfgD" ascii //weight: 5
        $x_1_4 = "CryptCreateHash" ascii //weight: 1
        $x_1_5 = "CryptHashData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

