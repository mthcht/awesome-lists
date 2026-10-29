rule PWS_Win64_RuatStealer_C_2147981147_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/RuatStealer.C!MTB"
        threat_id = "2147981147"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "RuatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RU-AT v1.0" ascii //weight: 1
        $x_1_2 = "SELECT origin_url, username_value, password_value" ascii //weight: 1
        $x_1_3 = "Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_4 = "Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_5 = "Brave-Browser\\User Data" ascii //weight: 1
        $x_1_6 = "os_crypt/app_bound_encrypted_key" ascii //weight: 1
        $x_1_7 = "[abe] DecryptData" ascii //weight: 1
        $x_1_8 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunRUAT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

