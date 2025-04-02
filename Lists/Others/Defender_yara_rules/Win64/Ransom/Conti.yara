rule Ransom_Win64_Conti_ZA_2147814691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.ZA"
        threat_id = "2147814691"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {43 69 04 81 51 2d 9e cc c1 c0 0f 69 c8 93 35 87 1b 33 f9 c1 c7 0d 81 c7 14 af dd fa 8d 3c bf 49 83 c0 01 75 db}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Conti_GHJ_2147817051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.GHJ!MTB"
        threat_id = "2147817051"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 c0 0f 69 c8 93 35 87 1b 33 f9 c1 c7 0d 81 c7 14 af dd fa 8d 3c bf 49 83 c0 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Conti_RPJ_2147827691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.RPJ!MTB"
        threat_id = "2147827691"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 f0 48 01 ca 0f b6 00 88 02 83 45 fc 01 8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 00 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 b3 56 c6 45 b4 69 c6 45 b5 72 c6 45 b6 74 c6 45 b7 75 c6 45 b8 61 c6 45 b9 6c c6 45 ba 41 c6 45 bb 6c c6 45 bc 6c c6 45 bd 6f c6 45 be 63}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 aa 6b c6 45 ab 65 c6 45 ac 72 c6 45 ad 6e c6 45 ae 65 c6 45 af 6c c6 45 b0 33 c6 45 b1 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Conti_MIO_2147901165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.MIO!MTB"
        threat_id = "2147901165"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d1 e8 8b c8 81 f1 78 3b f6 82 80 e2 01 0f 44 c8 8b c1 d1 e8 8b d0 81 f2 78 3b f6 82 80 e1 01 0f 44 d0 8b ca d1 e9 8b c1 35 78 3b f6 82 80 e2 ?? 0f 44 c1 49 83 e9 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Conti_MX_2147935760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.MX!MTB"
        threat_id = "2147935760"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_4 = "system_health.exe" ascii //weight: 1
        $x_1_5 = "Clear-ComputerRestorePoint -All" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Conti_QZ_2147937596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Conti.QZ!MTB"
        threat_id = "2147937596"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Conti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows" ascii //weight: 2
        $x_2_2 = "wmic shadowcopy delete" ascii //weight: 2
        $x_2_3 = "Clear-ComputerRestorePoint -All" ascii //weight: 2
        $x_2_4 = "system_health.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

