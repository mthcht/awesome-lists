rule Ransom_Win64_Sarcoma_BAA_2147938220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sarcoma.BAA!MTB"
        threat_id = "2147938220"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sarcoma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FAIL_STATE_NOTIFICATION.pdf" ascii //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-56] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00 2f 00 3f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-56] 2e 6f 6e 69 6f 6e 2f 3f}  //weight: 1, accuracy: Low
        $x_1_4 = "tor browser" ascii //weight: 1
        $x_1_5 = "Stolen" ascii //weight: 1
        $x_1_6 = ".lock" ascii //weight: 1
        $x_1_7 = "powershell -w h -c Start-Sleep -Seconds 5; Remove-Item -Force -Path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win64_Sarcoma_ASA_2147943558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Sarcoma.ASA!MTB"
        threat_id = "2147943558"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Sarcoma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 89 ca 45 01 c2 c1 c1 08 44 31 d2 01 cb c1 c2 10 41 31 df 41 01 d3 41 c1 c7 07 45 31 d8 41 c1 c0 0c 45 01 c2 44 31 d2 c1 c2 08 41 01 d3 45 31 d8 41 c1 c0 07}  //weight: 3, accuracy: High
        $x_2_2 = {31 e8 45 01 fa c1 c0 10 45 31 d6 41 c1 c6 08 44 01 f7 45 31 ee 41 c1 c6 10 41 31 ff 01 c7 45 01 f4 41 c1 c7 07 44 31 e6 c1 c6 0c 41 01 f5 45 31 ee 41 c1 c6 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

