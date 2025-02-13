rule Trojan_Win64_Polazert_GC_2147795260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Polazert.GC!MTB"
        threat_id = "2147795260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "\\APPDATA\\ROAMING" wide //weight: 1
        $x_1_4 = "\":\"change_status\",\"" wide //weight: 1
        $x_1_5 = "\",\"is_success\":" wide //weight: 1
        $x_1_6 = "Admin" wide //weight: 1
        $x_1_7 = "uniq_hash" wide //weight: 1
        $x_1_8 = "userprofile" wide //weight: 1
        $x_1_9 = "<RSAKeyValue><Modulus>" wide //weight: 1
        $x_1_10 = "Vista" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

