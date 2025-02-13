rule Ransom_Win32_Mortis_PA_2147892439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mortis.PA!MTB"
        threat_id = "2147892439"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mortis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Mortis" ascii //weight: 1
        $x_1_2 = "Your data has been stolen and encrypted by MortisLocker" ascii //weight: 1
        $x_1_3 = "\\MortisLocker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mortis_MA_2147900984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mortis.MA!MTB"
        threat_id = "2147900984"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mortis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MortisLocker.pdb" ascii //weight: 1
        $x_1_2 = "[*] AES Key:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

