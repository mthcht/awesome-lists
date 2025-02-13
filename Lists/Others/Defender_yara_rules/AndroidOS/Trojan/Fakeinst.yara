rule Trojan_AndroidOS_Fakeinst_I_2147839288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fakeinst.I!MTB"
        threat_id = "2147839288"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fakeinst"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isUkraineID" ascii //weight: 1
        $x_1_2 = "getAppName" ascii //weight: 1
        $x_1_3 = "isKZID" ascii //weight: 1
        $x_1_4 = "com/decryptstringmanager" ascii //weight: 1
        $x_1_5 = "startActivate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

