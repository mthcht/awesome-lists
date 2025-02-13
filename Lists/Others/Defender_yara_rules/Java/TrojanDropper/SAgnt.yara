rule TrojanDropper_Java_SAgnt_A_2147813256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Java/SAgnt.A!MTB"
        threat_id = "2147813256"
        type = "TrojanDropper"
        platform = "Java: Java binaries (classes)"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kIbwf02ldddd" ascii //weight: 1
        $x_1_2 = "get_crypted_filename" ascii //weight: 1
        $x_1_3 = "Mg1ShI8O9T06jJQDrljs" ascii //weight: 1
        $x_1_4 = "OBSrz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

