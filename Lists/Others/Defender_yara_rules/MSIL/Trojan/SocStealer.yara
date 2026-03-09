rule Trojan_MSIL_SocStealer_CQ_2147964365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SocStealer.CQ!MTB"
        threat_id = "2147964365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SocStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app_bound_encrypted_key" ascii //weight: 1
        $x_1_2 = "SELECT origin_url,username_value,password_value" ascii //weight: 1
        $x_1_3 = "FROM moz_places WHERE visit_count>0" ascii //weight: 1
        $x_1_4 = "payload.exe" ascii //weight: 1
        $x_1_5 = "screenshot.jpg" ascii //weight: 1
        $x_1_6 = "v20_decrypt" ascii //weight: 1
        $x_1_7 = "system_info.txt" ascii //weight: 1
        $x_1_8 = "logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

