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
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
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

rule Trojan_Linux_Kagentz_Z_2147967757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kagentz.Z!MTB"
        threat_id = "2147967757"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kagentz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agent/core.(*Agent).startHeartbeat" ascii //weight: 1
        $x_1_2 = "agent/core.(*Agent).sendHeartbeat" ascii //weight: 1
        $x_1_3 = "agent/core.(*Agent).sendResponse" ascii //weight: 1
        $x_1_4 = "agent/core.(*Agent).handlePing" ascii //weight: 1
        $x_1_5 = "/handlers/command.go" ascii //weight: 1
        $x_1_6 = "/handlers/process.go" ascii //weight: 1
        $x_1_7 = "/utils/machine_id.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

