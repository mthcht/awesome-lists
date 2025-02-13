rule Trojan_Linux_IPStorm_A_2147765286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/IPStorm.A!MTB"
        threat_id = "2147765286"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "IPStorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "storm/powershell.(*Backend).StartProcess" ascii //weight: 1
        $x_1_2 = "storm/backshell.StartServer" ascii //weight: 1
        $x_1_3 = "storm/reque_client/workers/brutessh" ascii //weight: 1
        $x_1_4 = "avbypass" ascii //weight: 1
        $x_1_5 = "storm/ddb" ascii //weight: 1
        $x_1_6 = "storm/malware-guard/malware-guard.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_IPStorm_B_2147890542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/IPStorm.B!MTB"
        threat_id = "2147890542"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "IPStorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "storm/storm_runtime" ascii //weight: 1
        $x_1_2 = "storm/malware-guard/malware-guard.go" ascii //weight: 1
        $x_1_3 = "storm/reque_client" ascii //weight: 1
        $x_1_4 = "storm/ddb" ascii //weight: 1
        $x_1_5 = "storm/backshell" ascii //weight: 1
        $x_1_6 = "/storm/statik/statik.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

