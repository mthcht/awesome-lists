rule Ransom_Win32_Ragnar_GG_2147753781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ragnar.GG!MTB"
        threat_id = "2147753781"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "---RAGNAR SECRET---" ascii //weight: 10
        $x_1_2 = "CryptEncrypt" ascii //weight: 1
        $x_1_3 = "$Recycle.Bin" ascii //weight: 1
        $x_1_4 = "autorun.inf" ascii //weight: 1
        $x_1_5 = "bootsect.bak" ascii //weight: 1
        $x_1_6 = "Tor browser" ascii //weight: 1
        $x_1_7 = "%s-%s-%s-%s-%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Ragnar_PA_2147837678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Ragnar.PA!MTB"
        threat_id = "2147837678"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragnar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sensitive files were COMPROMISED" ascii //weight: 1
        $x_1_2 = "encrypt your files and servers" ascii //weight: 1
        $x_1_3 = "everything will be PUBLISH" ascii //weight: 1
        $x_1_4 = "_README_NOTES_RAGNAR_" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

