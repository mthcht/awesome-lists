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

