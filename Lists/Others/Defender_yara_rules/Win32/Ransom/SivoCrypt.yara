rule Ransom_Win32_SivoCrypt_PA_2147776266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SivoCrypt.PA!MTB"
        threat_id = "2147776266"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SivoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".sivo" wide //weight: 1
        $x_1_2 = "\\sivo.pdb" ascii //weight: 1
        $x_1_3 = "Sivo-README.txt" ascii //weight: 1
        $x_1_4 = "EncryptedExt" ascii //weight: 1
        $x_1_5 = "wmic shadowcopy call create Volume=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

