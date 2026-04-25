rule Ransom_Win64_PayoutsKing_GXI_2147967767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/PayoutsKing.GXI!MTB"
        threat_id = "2147967767"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "PayoutsKing"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f 6f 30 66 0f ef b4 24 ?? ?? ?? ?? 66 0f 7f b4 24 ?? ?? ?? ?? 0f 28 40 10 0f 57 84 24 ?? ?? ?? ?? 0f 29 84 24 ?? ?? ?? ?? 48 8d 9c 24 ?? ?? ?? ?? 48 89 9c 24 ?? ?? ?? ?? 48 8d 8c 24}  //weight: 10, accuracy: Low
        $x_1_2 = "%s encrypt_init:%s" ascii //weight: 1
        $x_1_3 = "evp_pkey_decrypt_alloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

