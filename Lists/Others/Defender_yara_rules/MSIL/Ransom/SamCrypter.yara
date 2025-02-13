rule Ransom_MSIL_SamCrypter_PA_2147771217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SamCrypter.PA!MTB"
        threat_id = "2147771217"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SamCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Sam83Ransomware_unique_ID\\unique_id.txt" wide //weight: 1
        $x_1_2 = "encrypted by Mr SAM the Master" wide //weight: 1
        $x_1_3 = "DO NOT REPORT ANY OF OUR E-MAILS OR YOU WILL GET BUSTED" wide //weight: 1
        $x_1_4 = "cmd.exe /k vssadmin delete shadows /all" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

