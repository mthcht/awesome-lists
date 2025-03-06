rule Ransom_Win32_BlackSuit_AB_2147847897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSuit.AB!MTB"
        threat_id = "2147847897"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Extortioner named  BlackSuit has attacked your system" ascii //weight: 1
        $x_1_2 = "all your essential files were encrypted" ascii //weight: 1
        $x_1_3 = "Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_4 = "/deletevalue {current} safeboot" wide //weight: 1
        $x_1_5 = "encryptor\\Release\\encryptor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackSuit_YY_2147895349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSuit.YY!MTB"
        threat_id = "2147895349"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 98 8b 45 ec 8b 55 d4 01 02 8b 45 c4 03 45 90 03 45 ec 03 45 98 89 45 a4 [0-16] 8b 5d a4 2b d8 [0-16] 2b d8 [0-16] 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackSuit_AZ_2147900072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSuit.AZ!MTB"
        threat_id = "2147900072"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 8d 0c 16 83 e0 1f 42 8a 80 ?? ?? ?? ?? 32 04 0f 88 01 81 fa ?? ?? ?? ?? 72 e4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 8d 0c 37 33 d2 46 f7 74 ?? ?? 8a 82 ?? ?? ?? ?? 32 04 0b 88 01 81 fe ?? ?? ?? ?? 72 e1}  //weight: 1, accuracy: Low
        $x_10_3 = "readme.blacksuit.txt" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_BlackSuit_RHA_2147905840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSuit.RHA!MTB"
        threat_id = "2147905840"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "BEGIN RSA PUBLIC KEY-----MIICIjANBg" ascii //weight: 2
        $x_2_2 = "readme.blacksuit.txt" wide //weight: 2
        $x_2_3 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 21 0b 01 0e 22 00 c6 00 00 00 80 04}  //weight: 2, accuracy: Low
        $x_2_4 = {b8 01 00 00 00 c2 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_BlackSuit_CCJU_2147935299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackSuit.CCJU!MTB"
        threat_id = "2147935299"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackSuit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 04 32 33 d2 88 46 01 8b 44 24 24 03 c6 f7 74 24 10 0f b6 82 ?? ?? ?? ?? 8b 54 24 28 32 04 32 88 46 02 83 c6 05 8d 04 37}  //weight: 2, accuracy: Low
        $x_1_2 = ".chaos" wide //weight: 1
        $x_1_3 = "encrypt_step" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

