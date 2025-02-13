rule Ransom_MSIL_NoCry_MK_2147773603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NoCry.MK!MTB"
        threat_id = "2147773603"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NoCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "47"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "All Your Files Are Encrypted" ascii //weight: 10
        $x_10_2 = "Yes, You Can Recover All Your Files Easily And Quickly" ascii //weight: 10
        $x_10_3 = "I Will Send The Key To You For Decryption" ascii //weight: 10
        $x_5_4 = "NoCry Decryptor" ascii //weight: 5
        $x_1_5 = "Cry.img" ascii //weight: 1
        $x_10_6 = "How To Decrypt My Files.html" ascii //weight: 10
        $x_1_7 = "@yandex.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_NoCry_PAA_2147793739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NoCry.PAA!MTB"
        threat_id = "2147793739"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NoCry"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 00 75 00 6e 00 [0-2] 63 00 6f 00 75 00 6e 00 74 00 2e 00 63 00 72 00 79 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Select * from Win32_ComputerSystem" wide //weight: 1
        $x_1_3 = "Files Have Been Encrypted" wide //weight: 1
        $x_1_4 = "DetectVirtualMachine" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

