rule Ransom_Win32_Sage_AA_2147853272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Sage.AA!MTB"
        threat_id = "2147853272"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Sage"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sage encrypte" ascii //weight: 1
        $x_1_2 = "All your files have been encrypted with the public key" ascii //weight: 1
        $x_1_3 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_4 = "!Recovery_%s.txt" ascii //weight: 1
        $x_1_5 = "!Recovery_%s.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

