rule Ransom_Python_Filecoder_DA_2147939990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Python/Filecoder.DA!MTB"
        threat_id = "2147939990"
        type = "Ransom"
        platform = "Python: Python scripts"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "214"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell -C" ascii //weight: 100
        $x_100_2 = "Set-MpPreference" ascii //weight: 100
        $x_10_3 = "-SubmitSamplesConsent NeverSend" ascii //weight: 10
        $x_10_4 = "-MAPSReporting Disable" ascii //weight: 10
        $x_10_5 = "-EnableControlledFolderAccess Disabled" ascii //weight: 10
        $x_1_6 = "windows defender evasion successfull" ascii //weight: 1
        $x_1_7 = "taskkill /f /im explorer.exe" ascii //weight: 1
        $x_1_8 = "encrypted_data" ascii //weight: 1
        $x_1_9 = "encrypted successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

