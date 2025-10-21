rule Ransom_Win64_MonkeyCrypt_PB_2147955653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MonkeyCrypt.PB!MTB"
        threat_id = "2147955653"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MonkeyCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "monkey.monkey" ascii //weight: 3
        $x_1_2 = "How_to_recover_your_files.txt" ascii //weight: 1
        $x_1_3 = "vssadmin Delete Shadows /All /Quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

