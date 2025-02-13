rule Ransom_Win32_Gansom_AB_2147751378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gansom.AB!MTB"
        threat_id = "2147751378"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "repos\\ransomlol\\ransomlol\\obj\\Debug\\ransomlol.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Gansom_AC_2147752468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Gansom.AC!MTB"
        threat_id = "2147752468"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Gansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your file are crypted" wide //weight: 1
        $x_1_2 = "Your computer is temporarily blocked on several levels" wide //weight: 1
        $x_1_3 = "Applying strong military secret encryption algorithm" wide //weight: 1
        $x_1_4 = "Donations to the US presidential elections are accepted around the clock" wide //weight: 1
        $x_1_5 = "Desine sperare qui hic intras!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

