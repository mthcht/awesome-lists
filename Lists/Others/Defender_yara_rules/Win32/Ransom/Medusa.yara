rule Ransom_Win32_Medusa_PA_2147887431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Medusa.PA!MTB"
        threat_id = "2147887431"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Medusa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENCRYPTED" ascii //weight: 1
        $x_1_2 = "MEDUSA DECRYPTOR" ascii //weight: 1
        $x_1_3 = "G:\\Medusa\\Release\\gaze.pdb" ascii //weight: 1
        $x_1_4 = "powershell -executionpolicy bypass -File" ascii //weight: 1
        $x_1_5 = "PUBLIC KEY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

