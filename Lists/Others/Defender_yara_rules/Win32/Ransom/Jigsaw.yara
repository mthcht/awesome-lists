rule Ransom_Win32_Jigsaw_PA_2147751834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jigsaw.PA!MTB"
        threat_id = "2147751834"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jigsaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jigsaw-Ransomware-master" ascii //weight: 1
        $x_1_2 = "Your personal files are being deleted" wide //weight: 1
        $x_1_3 = "I've already encrypted your personal files, so you cannot access them" wide //weight: 1
        $x_1_4 = "Encryption Complete" wide //weight: 1
        $x_1_5 = "FucktheSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Jigsaw_SK_2147756580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Jigsaw.SK!MTB"
        threat_id = "2147756580"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Jigsaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Jigsaw.Resources" wide //weight: 1
        $x_1_2 = "All your file are encrypted by the 1789 ransomware" wide //weight: 1
        $x_1_3 = "FucktheSystem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

