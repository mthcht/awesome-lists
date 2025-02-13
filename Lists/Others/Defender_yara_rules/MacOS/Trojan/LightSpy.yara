rule Trojan_MacOS_LightSpy_A_2147907809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/LightSpy.A!MTB"
        threat_id = "2147907809"
        type = "Trojan"
        platform = "MacOS: "
        family = "LightSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Users/air/work/F_Warehouse/mac/new_plugins/" ascii //weight: 1
        $x_1_2 = "sendLogWithCmd" ascii //weight: 1
        $x_1_3 = "stopExecCmd" ascii //weight: 1
        $x_1_4 = "getCmdTypeWithCmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

