rule Ransom_Win32_BKRasnom_AA_2147853273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BKRasnom.AA!MTB"
        threat_id = "2147853273"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BKRasnom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\BKRansomware\\Release\\BKRansomware.pdb" ascii //weight: 1
        $x_1_2 = "gmreadme.txt.hainhc" wide //weight: 1
        $x_1_3 = "\\SYSTEM32\\chcp.com.hainhc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

