rule Ransom_Win32_Medusalocker_S_2147745543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Medusalocker.S!MSR"
        threat_id = "2147745543"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Medusalocker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".encrypted" wide //weight: 1
        $x_1_2 = "ConsentPromptBehaviorAdmin" wide //weight: 1
        $x_1_3 = "LOCKER" wide //weight: 1
        $x_1_4 = "recoveryenabled No" wide //weight: 1
        $x_1_5 = "Sleep at" wide //weight: 1
        $x_1_6 = "DELETE SYSTEMSTATEBACKUP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

