rule Ransom_Linux_DragonForce_A_2147946606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/DragonForce.A!MTB"
        threat_id = "2147946606"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "DragonForce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encrypted_note" ascii //weight: 1
        $x_1_2 = "vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_1_3 = "ECRYPT_encrypt_bytes" ascii //weight: 1
        $x_1_4 = "vim-cmd vmsvc/power.off" ascii //weight: 1
        $x_1_5 = "logger_encryption.cpp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

