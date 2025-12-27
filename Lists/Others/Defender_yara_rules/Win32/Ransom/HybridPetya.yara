rule Ransom_Win32_HybridPetya_PA_2147952195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HybridPetya.PA!MTB"
        threat_id = "2147952195"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HybridPetya"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_ReflectiveLoader@" ascii //weight: 1
        $x_1_2 = "\\EFI\\Microsoft\\Boot\\" ascii //weight: 1
        $x_1_3 = "YOUR_FILES_ARE_ENCRYPTED.TXT" ascii //weight: 1
        $x_3_4 = "Send your Bitcoin wallet ID and personal installation key to e-mail" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

