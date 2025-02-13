rule Virus_Win32_Almanahe_A_2147609041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Almanahe.gen!A"
        threat_id = "2147609041"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b b9 cd 04 00 00 80 ?? 19 ?? e2 fa eb 06 e8 ed ff ff ff}  //weight: 1, accuracy: Low
        $n_1_2 = "This folder has been created by SmartCOP Anti-Virus to immunize" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Virus_Win32_Almanahe_PABR_2147899054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Almanahe.PABR!MTB"
        threat_id = "2147899054"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 9e 04 00 00 80 04 19 59 e2 fa}  //weight: 1, accuracy: High
        $x_1_2 = {06 ec a4 bf 8c 34 bf da 94 a6 b3 ce 4e e4 4c 5c cc 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Almanahe_PACA_2147899055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Almanahe.PACA!MTB"
        threat_id = "2147899055"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Almanahe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {37 47 b7 80 c5 82 ?? ?? ?? ?? b9 2c cd a1 08 2c 7c 44 44 44 43 63 c0 0d d1 01 05 83 bc a0 7f 99 56}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 9e 04 00 00 80 04 19 a2 e2 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

