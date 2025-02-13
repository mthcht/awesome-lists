rule Trojan_AndroidOS_Idiqut_A_2147901590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Idiqut.A!MTB"
        threat_id = "2147901590"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Idiqut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app_sikhywis_ca55200e" ascii //weight: 1
        $x_1_2 = "com.sec.whisky.Scotch" ascii //weight: 1
        $x_1_3 = "/scotch.jar" ascii //weight: 1
        $x_1_4 = "bin2md5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

