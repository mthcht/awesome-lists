rule Ransom_Win32_Inc_MA_2147901278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Inc.MA!MTB"
        threat_id = "2147901278"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Inc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ":\\INC-README.txt" wide //weight: 10
        $x_10_2 = "~~~~ INC Ransom ~~~~" ascii //weight: 10
        $x_10_3 = {68 74 74 70 3a 2f 2f 69 6e 63 70 61 79 [0-80] 2e 6f 6e 69 6f 6e}  //weight: 10, accuracy: Low
        $x_1_4 = "If you do not pay the ransom, we will attack your company again in the future" ascii //weight: 1
        $x_1_5 = "Don't go to recovery companies" ascii //weight: 1
        $x_1_6 = "The police and FBI won't protect you from repeated attacks" ascii //weight: 1
        $x_1_7 = "Paying the ransom to us is much cheaper and more profitable than paying fines and legal fees" ascii //weight: 1
        $x_1_8 = "Warning! Don't delete or modify encrypted files, it will lead to problems with decryption of files" ascii //weight: 1
        $x_1_9 = "Your data is stolen and encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Inc_MKV_2147913960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Inc.MKV!MTB"
        threat_id = "2147913960"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Inc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 f6 8a 44 35 ec 46 30 04 3a 47 3b 7d 08 72 ae}  //weight: 5, accuracy: High
        $x_2_2 = "~~~~ INC Ransom ~~~~" ascii //weight: 2
        $x_2_3 = "Your data is stolen and encrypted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

