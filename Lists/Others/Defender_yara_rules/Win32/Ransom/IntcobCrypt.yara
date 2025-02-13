rule Ransom_Win32_IntcobCrypt_PA_2147806017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/IntcobCrypt.PA!MTB"
        threat_id = "2147806017"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "IntcobCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "is_it_possible_return_back lost documents.txt" wide //weight: 1
        $x_1_2 = ".intercobros-9k7syfus" wide //weight: 1
        $x_1_3 = "cynet ransom protection" wide //weight: 1
        $x_1_4 = "EncryptionStage1 begin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

