rule Trojan_Linux_Bashlite_A_2147937407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bashlite.A!MTB"
        threat_id = "2147937407"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bashlite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "(crontab -l ; echo \"@reboot %s\") | crontab -" ascii //weight: 2
        $x_2_2 = "/bin/curl -k -L --output" ascii //weight: 2
        $x_1_3 = "/watchdog" ascii //weight: 1
        $x_1_4 = "WantedBy=multi-user.target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

