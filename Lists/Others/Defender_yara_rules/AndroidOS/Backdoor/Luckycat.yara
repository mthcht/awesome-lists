rule Backdoor_AndroidOS_Luckycat_A_2147660622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Luckycat.A"
        threat_id = "2147660622"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Luckycat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+create socket ok!" ascii //weight: 1
        $x_1_2 = "greenfuns.3322.org" ascii //weight: 1
        $x_1_3 = "NetworkPIN" ascii //weight: 1
        $x_1_4 = "socke close" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Luckycat_C_2147733271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Luckycat.C"
        threat_id = "2147733271"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Luckycat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://mondaynews.tk/cam/cm.php?v=" ascii //weight: 1
        $x_1_2 = "&chmod -R 777 /data/data/com.tencent.mm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Luckycat_B_2147734140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Luckycat.B"
        threat_id = "2147734140"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Luckycat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "+create socket ok!" ascii //weight: 1
        $x_1_2 = "!Lcom/baidu/mapapi/TransitOverlay" ascii //weight: 1
        $x_1_3 = "&chmod -R 777 /data/data/com.tencent.mm" ascii //weight: 1
        $x_1_4 = "chmod 777 /data/data" ascii //weight: 1
        $x_1_5 = "socke close" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

