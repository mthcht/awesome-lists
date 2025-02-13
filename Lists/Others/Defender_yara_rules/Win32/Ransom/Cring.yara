rule Ransom_Win32_Cring_AA_2147774327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cring.AA!MTB"
        threat_id = "2147774327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cring"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deReadMe!!!.txt" ascii //weight: 1
        $x_1_2 = "donot cry :)" wide //weight: 1
        $x_1_3 = ".cring" ascii //weight: 1
        $x_1_4 = "killme.bat" wide //weight: 1
        $x_1_5 = "Crypt3r" ascii //weight: 1
        $x_1_6 = "Finished! :(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

