rule Ransom_Win32_Lambda_MA_2147892649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lambda.MA!MTB"
        threat_id = "2147892649"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lambda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 05 c3 ff ff 7f f7 f3 8d 04 31 41 30 10 3b cf 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lambda_MB_2147892650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lambda.MB!MTB"
        threat_id = "2147892650"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lambda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LAMBDA_README.txt" wide //weight: 1
        $x_1_2 = "RECYCLER" wide //weight: 1
        $x_1_3 = "SELECT * FROM Win32_ShadowCopy" wide //weight: 1
        $x_1_4 = "ROOT\\CIMV2" wide //weight: 1
        $x_1_5 = "\\LambdaDebug.txt" wide //weight: 1
        $x_1_6 = "Global\\LambdaMutex" wide //weight: 1
        $x_1_7 = "Lambda Ransomware" ascii //weight: 1
        $x_1_8 = "All your files are encrypted and stolen, but you need to follow our instructions. otherwise, you cant return your data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

