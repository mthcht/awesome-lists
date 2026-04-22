rule Trojan_Linux_Kagentz_DA_2147967487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kagentz.DA!MTB"
        threat_id = "2147967487"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kagentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Heartbeat sent: uptime=%ds, cpu=%.1f%%, mem=%.1f%%, disk=%.1f%%" ascii //weight: 1
        $x_1_2 = "nkn.Client" ascii //weight: 1
        $x_1_3 = "Shell output sent successfully" ascii //weight: 1
        $x_1_4 = "Agent binary deleted successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

