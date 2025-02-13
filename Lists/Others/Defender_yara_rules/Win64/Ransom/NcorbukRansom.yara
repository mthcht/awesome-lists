rule Ransom_Win64_NcorbukRansom_YAA_2147919387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/NcorbukRansom.YAA!MTB"
        threat_id = "2147919387"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "NcorbukRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desktop/EMAIL_ME.txt" ascii //weight: 1
        $x_1_2 = "RansomWare.encrypt_fernet_key" ascii //weight: 1
        $x_1_3 = "change_desktop_background" ascii //weight: 1
        $x_1_4 = "RANSOM_NOTE.txt" ascii //weight: 1
        $x_1_5 = "encrypted with an Military" ascii //weight: 1
        $x_1_6 = "address for payment" ascii //weight: 1
        $x_1_7 = "to decrypt all files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

