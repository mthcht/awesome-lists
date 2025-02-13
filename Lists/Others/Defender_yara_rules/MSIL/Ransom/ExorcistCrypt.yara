rule Ransom_MSIL_ExorcistCrypt_PA_2147771644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ExorcistCrypt.PA!MTB"
        threat_id = "2147771644"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ExorcistCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DisableTaskMgr" wide //weight: 1
        $x_1_2 = "Rasomware2.0" wide //weight: 1
        $x_1_3 = "ANNABELLE RANSOMWARE" wide //weight: 1
        $x_1_4 = {5c 65 78 6f 72 63 69 73 74 5c 65 78 6f 72 63 69 73 74 5c [0-16] 5c [0-16] 5c 65 78 6f 72 63 69 73 74 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

