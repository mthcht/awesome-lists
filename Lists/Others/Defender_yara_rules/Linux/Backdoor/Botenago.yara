rule Backdoor_Linux_Botenago_B_2147809957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Botenago.B!MTB"
        threat_id = "2147809957"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Botenago"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.telnetLoadDroppers" ascii //weight: 1
        $x_1_2 = "main.telnetHasBusybox" ascii //weight: 1
        $x_1_3 = "main.infectFunctionBroadcom" ascii //weight: 1
        $x_1_4 = "main.infectFunctionGponFiber" ascii //weight: 1
        $x_1_5 = "main.infectFunctionMagic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

