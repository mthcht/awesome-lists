rule Backdoor_Linux_IoTReaper_2147724182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/IoTReaper"
        threat_id = "2147724182"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "IoTReaper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nmnlmevdm" ascii //weight: 1
        $x_1_2 = "XMNNCPF" ascii //weight: 1
        $x_1_3 = "egvnmacnkr" ascii //weight: 1
        $x_1_4 = "GLC@NG" ascii //weight: 1
        $x_1_5 = "Q[QVGO" ascii //weight: 1
        $x_1_6 = "LAMPPGAV" ascii //weight: 1
        $x_1_7 = "AJWLIGF" ascii //weight: 1
        $x_1_8 = "GET /shell?cat%%20/etc/passwd" ascii //weight: 1
        $x_1_9 = "GET /system.ini?loginuse&loginpas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

