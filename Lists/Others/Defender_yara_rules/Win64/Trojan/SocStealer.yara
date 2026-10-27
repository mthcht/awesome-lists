rule Trojan_Win64_SocStealer_KK_2147981005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SocStealer.KK!MTB"
        threat_id = "2147981005"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SocStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SELECT origin_url,username_value,password_value FROM logins" ascii //weight: 5
        $x_4_2 = "SELECT host_key,name,encrypted_value FROM cookies" ascii //weight: 4
        $x_3_3 = "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted" ascii //weight: 3
        $x_2_4 = "\\Exodus\\exodus.wallet\\seed.seco" wide //weight: 2
        $x_1_5 = "lunar_payload.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

