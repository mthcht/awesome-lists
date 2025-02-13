rule Ransom_MSIL_HarpoonLocker_PA_2147799578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HarpoonLocker.PA!MTB"
        threat_id = "2147799578"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HarpoonLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\restore-files.txt" wide //weight: 1
        $x_1_2 = ".locked" wide //weight: 1
        $x_1_3 = "bcdedit /deletevalue {current} safeboot" wide //weight: 1
        $x_1_4 = "shutdown /r /t 0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

