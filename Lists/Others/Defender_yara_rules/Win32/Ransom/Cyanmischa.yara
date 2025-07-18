rule Ransom_Win32_Cyanmischa_EA_2147939216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cyanmischa.EA!MTB"
        threat_id = "2147939216"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyanmischa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 34 5a 8a 04 19 88 46 01 8b 3d ?? ?? ?? ?? c6 04 5f 0b 43 81 fb d0 07 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cyanmischa_MKV_2147946802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cyanmischa.MKV!MTB"
        threat_id = "2147946802"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyanmischa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CYANMISCHA RANSOMWARE PERFC FILE!!" ascii //weight: 1
        $x_1_2 = "You became victim of the CYANMISCHA RANSOMWARE!!!" ascii //weight: 1
        $x_1_3 = "files in your computer have been safely encrypted by cyanmischa" ascii //weight: 1
        $x_1_4 = "Final decryption key" ascii //weight: 1
        $x_1_5 = "cyanmischa decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

