rule Ransom_Win32_HQCrypt_PA_2147792995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HQCrypt.PA!MTB"
        threat_id = "2147792995"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HQCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\How to decrypt files.html" ascii //weight: 1
        $x_1_2 = "ALL YOUR PERSONAL FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "\\al-madani\\Release\\HQ_52_42.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

