rule Ransom_Win32_Dharma_PAA_2147793524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Dharma.PAA!MTB"
        threat_id = "2147793524"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Dharma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "DHARMADECRYPT" wide //weight: 5
        $x_5_2 = "schtasks /CREATE /SC ONLOGON /TN DHARMA /TR" ascii //weight: 5
        $x_1_3 = "DisableTaskMgr" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "start cmd.exe /c taskkill /t /f /im" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

