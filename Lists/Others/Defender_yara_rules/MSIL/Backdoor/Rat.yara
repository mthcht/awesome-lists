rule Backdoor_MSIL_Rat_RHA_2147912213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Rat.RHA!MTB"
        threat_id = "2147912213"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "file:" wide //weight: 1
        $x_1_2 = "Location" wide //weight: 1
        $x_1_3 = "explorer" wide //weight: 1
        $x_1_4 = "taskkill /IM cmstp.exe /F" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 45 00 58 00 50 00 4c 00 4f 00 52 00 45 00 52 00 2e 00 45 00 58 00 45 00}  //weight: 1, accuracy: Low
        $x_2_7 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 00 00 ?? 01 00 00 d2}  //weight: 2, accuracy: Low
        $x_2_8 = {ec 1f 00 00 01 00 40 40 00 00 01 00 20 00 28 42 00 00 02 00 30 30 00 00 01 00 20 00 a8 25 00 00 03 00 28 28 00 00 01 00 20 00 68 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

