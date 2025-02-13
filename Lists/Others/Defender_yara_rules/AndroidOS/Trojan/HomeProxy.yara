rule Trojan_AndroidOS_HomeProxy_A_2147762598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HomeProxy.A!MTB"
        threat_id = "2147762598"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HomeProxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/api/ping-apk?id=" ascii //weight: 1
        $x_1_2 = "zip_file.comment" ascii //weight: 1
        $x_1_3 = "/RestartServiceReceiver;" ascii //weight: 1
        $x_1_4 = "socks_password" ascii //weight: 1
        $x_1_5 = "hidden_icon" ascii //weight: 1
        $x_1_6 = {0e 7b 22 72 65 73 75 6c 74 22 3a 22 33 22 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

