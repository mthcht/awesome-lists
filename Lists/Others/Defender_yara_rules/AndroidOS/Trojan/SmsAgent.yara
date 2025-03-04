rule Trojan_AndroidOS_Smsagent_A_2147844720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Smsagent.A"
        threat_id = "2147844720"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Smsagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://affmob.tornika.com/service_lib.php" ascii //weight: 1
        $x_1_2 = "com.bjoeajfpa" ascii //weight: 1
        $x_1_3 = "sys_send_contents" ascii //weight: 1
        $x_1_4 = "TNKLIB ||| STARTING SERVICE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

