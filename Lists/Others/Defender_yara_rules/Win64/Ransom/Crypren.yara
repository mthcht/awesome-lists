rule Ransom_Win64_Crypren_A_2147945777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypren.A!MTB"
        threat_id = "2147945777"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" ascii //weight: 1
        $x_1_2 = "Decrypt Files" ascii //weight: 1
        $x_1_3 = "Decryption would run here." ascii //weight: 1
        $x_1_4 = "Incorrect password." ascii //weight: 1
        $x_1_5 = "RansomSimWnd" ascii //weight: 1
        $x_1_6 = "Your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Crypren_NITE_2147948092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypren.NITE!MTB"
        threat_id = "2147948092"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypren"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 95 40 11 00 00 48 8d 0d 4c ?? 00 00 48 8d 85 10 10 00 00 49 89 d1 49 89 c8 ba 04 01 00 00 48 89 c1 e8 fc 14 00 00 48 8d 15 38 ?? 00 00 48 8d 85 10 10 00 00 48 89 c1 e8 ee 75 00 00 48 89 85 20 11 00 00 48 83 bd 20 11 00 00 00 75 23 48 8b 85 28 11 00 00 48 89 c1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 85 1c 11 00 00 89 45 ec 48 8b 85 28 11 00 00 48 89 c1 e8 78 74 00 00 89 85 18 11 00 00 48 8b 85 00 10 00 00 8b 8d 18 11 00 00 c7 44 24 30 00 10 00 00 48 8d 55 ec 48 89 54 24 28 48 8d 55 f0 48 89 54 24 20 41 b9 00 00 00 00 41 89 c8 ba 00 00 00 00 48 89 c1 48 8b 05 8b da 00 00 ff d0 8b 45 ec 89 c1 48 8b 95 20 11 00 00 48 8d 45 f0 49 89 d1 49 89 c8 ba 01 00 00 00 48 89 c1 e8 3e 74 00 00 48 8b 95 28 11 00 00 48 8d 45 f0 49 89 d1 41 b8 00 10 00 00 ba 01 00 00 00 48 89 c1 e8 0d 74 00 00 89 85 1c 11 00 00 83 bd 1c 11 00 00 00 0f 85 4a ff ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "Encrypted and deleted" ascii //weight: 1
        $x_1_4 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

