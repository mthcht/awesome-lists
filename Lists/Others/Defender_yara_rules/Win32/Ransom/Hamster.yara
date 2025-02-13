rule Ransom_Win32_Hamster_AA_2147799277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hamster.AA!MTB"
        threat_id = "2147799277"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hamster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "encrypted all the stuff" ascii //weight: 1
        $x_1_3 = ".hamster" wide //weight: 1
        $x_1_4 = "How To decrypt.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

