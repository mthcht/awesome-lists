rule Ransom_Win32_Khaminga_A_2147726401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Khaminga.A"
        threat_id = "2147726401"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Khaminga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".ladon" ascii //weight: 1
        $x_1_2 = "Cyka Blykat" ascii //weight: 1
        $x_1_3 = "cdmsxo25y4lfht6v.onion.casa" ascii //weight: 1
        $x_1_4 = "\\READ_ME.html" ascii //weight: 1
        $x_1_5 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_6 = "wmic.exe shadowcopy delete /nointeractive" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

