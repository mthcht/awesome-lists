rule TrojanDropper_Java_Malscript_A_2147761610_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/Malscript.A!MTB"
        threat_id = "2147761610"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "Malscript"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "woiauczmea/Mbsiblylsmm" ascii //weight: 1
        $x_1_2 = "futiqvqhhy.js" ascii //weight: 1
        $x_1_3 = "resources/sdbjzjmiuv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

