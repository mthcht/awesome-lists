rule PWS_Win64_LotusHarvest_CI_2147959209_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/LotusHarvest.CI!MTB"
        threat_id = "2147959209"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "LotusHarvest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "decryptedPassword" ascii //weight: 2
        $x_2_2 = "computerName" ascii //weight: 2
        $x_2_3 = "userName" ascii //weight: 2
        $x_2_4 = "SELECT origin_url, username_value, password_value, date_created FROM logins" ascii //weight: 2
        $x_2_5 = "Chrome\\User Data" ascii //weight: 2
        $x_2_6 = "Edge\\User Data" ascii //weight: 2
        $x_2_7 = "computer_name\":\"%s\",\"user_name\":\"%s\",\"data\":" ascii //weight: 2
        $x_2_8 = "type\":\"passwords\",\"entries\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

