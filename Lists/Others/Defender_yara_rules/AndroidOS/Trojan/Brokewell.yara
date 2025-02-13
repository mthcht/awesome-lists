rule Trojan_AndroidOS_Brokewell_A_2147909624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brokewell.A"
        threat_id = "2147909624"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brokewell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aWlpaWlpaWlpaWlpaWlpaeVU3JHU53D2l969o/BN9rw=" ascii //weight: 1
        $x_1_2 = "QpH4V84hWonUevrc9gjpw=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Brokewell_A_2147911218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Brokewell.A!MTB"
        threat_id = "2147911218"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Brokewell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/webv/dump-cookies" ascii //weight: 1
        $x_1_2 = "askLOCKPIN" ascii //weight: 1
        $x_1_3 = "WebvInject" ascii //weight: 1
        $x_1_4 = "takeScreenshot" ascii //weight: 1
        $x_1_5 = "com/brkwl/upstracking/ScRecSrvc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

