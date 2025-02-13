rule Trojan_AndroidOS_AgentTriada_A_2147793157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AgentTriada.A"
        threat_id = "2147793157"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AgentTriada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "create table MulitiTabLe" ascii //weight: 5
        $x_5_2 = "com.cnmaind.cgo" ascii //weight: 5
        $x_5_3 = "fetchCodeURL" ascii //weight: 5
        $x_5_4 = "/reg/i" ascii //weight: 5
        $x_5_5 = "download start" ascii //weight: 5
        $x_5_6 = "syspatch" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

