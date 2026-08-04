rule Trojan_MSIL_Stealz_CZ_2147975228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealz.CZ!MTB"
        threat_id = "2147975228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app_bound_encrypted_key" wide //weight: 1
        $x_1_2 = "logins" wide //weight: 1
        $x_1_3 = "encryptedUsername" wide //weight: 1
        $x_1_4 = "encryptedPassword" wide //weight: 1
        $x_1_5 = "Chrome\\User Data" wide //weight: 1
        $x_1_6 = "Firefox\\Profiles" wide //weight: 1
        $x_1_7 = "encrypted_key\":\"" wide //weight: 1
        $x_1_8 = "\\Login Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

