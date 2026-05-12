rule Backdoor_Linux_PAMBackdoor_DA_2147969038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/PAMBackdoor.DA!MTB"
        threat_id = "2147969038"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "PAMBackdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "48"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "hostname=%s&username=%s&password=%s&port=%s&intranetip=%s" ascii //weight: 10
        $x_10_2 = "hostname=%s&install=install&intranetip=%s" ascii //weight: 10
        $x_10_3 = "blackinstall" ascii //weight: 10
        $x_10_4 = "/etc/ssh/sshd_config" ascii //weight: 10
        $x_1_5 = "pam_sm_authenticate" ascii //weight: 1
        $x_1_6 = "pam_get_authtok" ascii //weight: 1
        $x_1_7 = "curl_easy_perform" ascii //weight: 1
        $x_1_8 = "getspnam" ascii //weight: 1
        $x_1_9 = "write_data" ascii //weight: 1
        $x_1_10 = "sendMessage" ascii //weight: 1
        $x_1_11 = "getip" ascii //weight: 1
        $x_1_12 = "Username:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

