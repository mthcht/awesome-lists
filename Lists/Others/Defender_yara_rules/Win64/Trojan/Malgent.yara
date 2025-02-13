rule Trojan_Win64_Malgent_DSG_2147815604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgent.DSG!MSR"
        threat_id = "2147815604"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgent"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "Software\\Microsoft\\Office\\KMSAuto.dll" wide //weight: 100
        $x_100_2 = "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run" wide //weight: 100
        $x_100_3 = "Windows System Library DLL" wide //weight: 100
        $x_100_4 = "movie.youtoboo.kro.kr" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Malgent_MA_2147898645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgent.MA!MTB"
        threat_id = "2147898645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 fe 3d 2a be 1c 66 81 39 4d 5a 23 bc 19 6f 7f ff 3f 75 47 48 63 41 3c 48 01 c8 81 38 50 45 1c 38 8b 48 18 56 f9 0b 01 74 ed f7 ff bb 09 0d 02}  //weight: 10, accuracy: High
        $x_2_2 = {10 10 84 bc df b5 76 0e 22 0d 10 f8 23 0f 95 c2 0f b6 d2 aa 36 ef b6 ef ff 89 15 90 1f 3d 01 b9 02 2e 83 38 9c 05 b9 c9 e8 dc 57 9a d8 9f cd 6c}  //weight: 2, accuracy: High
        $x_2_3 = {10 10 84 bc df b5 76 0e 22 0d 10 f8 23 0f 95 c2 0f b6 d2 aa 36 bb ed db fe 89 15 90 3f 0a b9 02 2e 83 38 9c 05 b9 c9 e8 fc f6 67 33 db 66 9a 08}  //weight: 2, accuracy: High
        $x_2_4 = {f0 00 2e 02 0b 02 02 27 00 40 7f 00 00 10 00 00 00 d0 c9 00 e0 16 49 01 00 e0 c9 00 00 00 00 40 01 00 00 00 00 10 00 00 00 02}  //weight: 2, accuracy: High
        $x_2_5 = {f0 00 2e 02 0b 02 02 28 00 50 7f 00 00 10 00 00 00 e0 c9 00 60 34 49 01 00 f0 c9 00 00 00 00 40 01 00 00 00 00 10 00 00 00 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Malgent_NM_2147900462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Malgent.NM!MTB"
        threat_id = "2147900462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 6f fc ff ff 8a d8 8b 0d ?? ?? ?? ?? 83 f9 01 0f 84 1d 01 00 00 85 c9 75 4a c7 05 e8 61 05 00 ?? ?? ?? ?? 48 8d 15 a1 f9 02 00 48 8d 0d ?? ?? ?? ?? e8 f1 5a 01}  //weight: 5, accuracy: Low
        $x_1_2 = "sdsdsdsds.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

