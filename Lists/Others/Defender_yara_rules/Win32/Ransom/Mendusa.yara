rule Ransom_Win32_Mendusa_A_2147744241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mendusa.A!MSR"
        threat_id = "2147744241"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mendusa"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MedusaLocker.pdb" ascii //weight: 10
        $x_1_2 = "vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_3 = "wmic.exe SHADOWCOPY /nointeractive" wide //weight: 1
        $x_1_4 = "bcdedit.exe /set {default} recoveryenabled No" wide //weight: 1
        $x_1_5 = "wbadmin DELETE SYSTEMSTATEBACKUP" wide //weight: 1
        $x_1_6 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

