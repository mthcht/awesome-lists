rule Ransom_Win32_Cobra_AA_2147756840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cobra.AA!MTB"
        threat_id = "2147756840"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Cobra" wide //weight: 1
        $x_1_2 = "Ransomware" ascii //weight: 1
        $x_1_3 = "Your have been encrypted!" wide //weight: 1
        $x_1_4 = "Your files have been encrypted!" wide //weight: 1
        $x_1_5 = "Cobra_Locker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Cobra_AB_2147759078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cobra.AB!MTB"
        threat_id = "2147759078"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Cobra" ascii //weight: 1
        $x_1_2 = "ransomware" ascii //weight: 1
        $x_1_3 = "All your important files are encrypted!" ascii //weight: 1
        $x_1_4 = "Cobra_Locker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

