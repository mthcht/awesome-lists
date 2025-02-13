rule Backdoor_MacOS_Empyre_F_2147852240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Empyre.F!MTB"
        threat_id = "2147852240"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Empyre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_activateStager" ascii //weight: 1
        $x_1_2 = "_initializer" ascii //weight: 1
        $x_1_3 = "_Py_Initialize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Empyre_I_2147888109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Empyre.I!MTB"
        threat_id = "2147888109"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Empyre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "activateStager" ascii //weight: 1
        $x_1_2 = "templateDylib.c" ascii //weight: 1
        $x_1_3 = {62 61 73 65 36 34 [0-16] 65 78 65 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

