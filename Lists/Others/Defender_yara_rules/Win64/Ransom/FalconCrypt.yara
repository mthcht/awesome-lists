rule Ransom_Win64_FalconCrypt_YAB_2147917191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/FalconCrypt.YAB!MTB"
        threat_id = "2147917191"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "FalconCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "malcrypt.pdb" ascii //weight: 1
        $x_1_2 = "library\\core\\src\\escape.rs" ascii //weight: 1
        $x_1_3 = "C:\\Users\\falconDesktopencryption_note.txt" ascii //weight: 1
        $x_1_4 = "Your files have been encrypted by Malcrypt" ascii //weight: 1
        $x_1_5 = "you must pay a ransom of" ascii //weight: 1
        $x_1_6 = "To unlock your files, follow these steps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

