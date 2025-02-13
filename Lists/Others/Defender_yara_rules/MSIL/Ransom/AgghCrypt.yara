rule Ransom_MSIL_AgghCrypt_PA_2147774203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/AgghCrypt.PA!MTB"
        threat_id = "2147774203"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgghCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "downloadfromweb" ascii //weight: 1
        $x_1_2 = "payload" ascii //weight: 1
        $x_1_3 = "RememberThatThisRansomwareIsCodedForEducationnalPurposes" ascii //weight: 1
        $x_1_4 = "\\svchost.exe" wide //weight: 1
        $x_1_5 = "runas" wide //weight: 1
        $x_1_6 = "/C choice /C Y /N /D Y /T 1 & Del" wide //weight: 1
        $x_1_7 = {5c 78 36 35 34 35 34 5c [0-16] 5c [0-16] 5c 78 36 35 34 35 34 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

