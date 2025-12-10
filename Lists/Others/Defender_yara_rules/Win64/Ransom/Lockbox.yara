rule Ransom_Win64_Lockbox_CI_2147959128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Lockbox.CI!MTB"
        threat_id = "2147959128"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Lockbox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Failed to encrypt nonce" ascii //weight: 2
        $x_2_2 = "Failed to encrypt key" ascii //weight: 2
        $x_2_3 = "[+] Encrypting file:" ascii //weight: 2
        $x_2_4 = "ANTI_ANALYSIS" ascii //weight: 2
        $x_2_5 = "COMPUTERNAME" ascii //weight: 2
        $x_2_6 = "nothing to encrypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

