rule Trojan_Linux_SparkRAT_B_2147921861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SparkRAT.B!MTB"
        threat_id = "2147921861"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SparkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spark/modules.CPU" ascii //weight: 1
        $x_1_2 = "desktop.(*screen).capture" ascii //weight: 1
        $x_1_3 = "Spark/client/service/desktop.KillDesktop" ascii //weight: 1
        $x_1_4 = "Spark/client/common.(*Conn).GetSecretHex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_SparkRAT_C_2147923438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SparkRAT.C!MTB"
        threat_id = "2147923438"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SparkRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Spark/client/service/screenshot.GetScreenshot" ascii //weight: 3
        $x_3_2 = "Spark/client/common.(*Conn).SendData" ascii //weight: 3
        $x_1_3 = "Spark/client/service/desktop.KillDesktop" ascii //weight: 1
        $x_1_4 = "Spark/client/core.getDesktop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

