rule Virus_Win32_Otfrem_EM_2147912935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Otfrem.EM!MTB"
        threat_id = "2147912935"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Otfrem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gadis_Noya" ascii //weight: 1
        $x_1_2 = "Gadis_A_Noya" ascii //weight: 1
        $x_1_3 = "Poenya Koe\\Copy File dri Flash\\shell32\\ProjShell32.vbp" ascii //weight: 1
        $x_1_4 = "Hey this is a sample" ascii //weight: 1
        $x_1_5 = "scripting.filesystemobject" ascii //weight: 1
        $x_1_6 = "getspecialfolder" ascii //weight: 1
        $x_1_7 = "OTifVTa!XkX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

