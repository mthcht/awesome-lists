rule Ransom_Win64_LockZ_YAF_2147944780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockZ.YAF!MTB"
        threat_id = "2147944780"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get your files back" ascii //weight: 1
        $x_1_2 = "unlock files yourself" ascii //weight: 1
        $x_1_3 = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass" ascii //weight: 1
        $x_1_4 = "infected by **LockZ**" ascii //weight: 1
        $x_1_5 = "del /q /f" ascii //weight: 1
        $x_1_6 = "dirEncryption.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

