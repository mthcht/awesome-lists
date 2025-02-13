rule Ransom_Win32_BlackBasta_PA_2147845203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BlackBasta.PA!MTB"
        threat_id = "2147845203"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackBasta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".basta" wide //weight: 1
        $x_1_2 = "readme.txt" wide //weight: 1
        $x_1_3 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "Your data are stolen and encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

