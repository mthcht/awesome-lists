rule Trojan_MacOS_SparkRAT_A_2147919776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SparkRAT.A!MTB"
        threat_id = "2147919776"
        type = "Trojan"
        platform = "MacOS: "
        family = "SparkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spark/client/service/file.UploadFiles" ascii //weight: 1
        $x_1_2 = "Spark/client/service/basic.Shutdown" ascii //weight: 1
        $x_1_3 = "Spark/client/common.(*Conn).GetSecret" ascii //weight: 1
        $x_1_4 = "Spark/client/service/desktop.KillDesktop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

