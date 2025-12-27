rule Ransom_Win64_ZantaCrypt_PA_2147959652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/ZantaCrypt.PA!MTB"
        threat_id = "2147959652"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "ZantaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ZANTA_READ_ME.txt" wide //weight: 2
        $x_3_2 = "Global\\ZantaUltimaMutex" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

