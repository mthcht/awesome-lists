rule HackTool_MacOS_Keygen_2147748134_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Keygen!MTB"
        threat_id = "2147748134"
        type = "HackTool"
        platform = "MacOS: "
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 4f 52 45 20 4b 65 79 67 65 6e 2e 62 75 69 6c 64 2f 4f 62 6a 65 63 74 73 2d 6e 6f 72 6d 61 6c 2f [0-4] 2f 6d 61 69 6e 2e 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {43 4f 52 45 5f 4b 47 2e 62 75 69 6c 64 2f 4f 62 6a 65 63 74 73 2d 6e 6f 72 6d 61 6c 2f [0-4] 2f 6d 61 69 6e 2e 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "KGSerialNumberGenerator createSerial:" ascii //weight: 1
        $x_1_4 = "_mouseIsHovering" ascii //weight: 1
        $x_1_5 = "CORE Keygen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_MacOS_Keygen_TA_2147808760_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Keygen.TA!MTB"
        threat_id = "2147808760"
        type = "HackTool"
        platform = "MacOS: "
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CORE Keygen" ascii //weight: 1
        $x_1_2 = "SerialFieldBG" ascii //weight: 1
        $x_1_3 = "KGSerialNumberGenerator" ascii //weight: 1
        $x_1_4 = "mouseIsHovering" ascii //weight: 1
        $x_1_5 = "Patcher" ascii //weight: 1
        $x_1_6 = "createSerial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_MacOS_Keygen_A_2147838015_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Keygen.A!MTB"
        threat_id = "2147838015"
        type = "HackTool"
        platform = "MacOS: "
        family = "Keygen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ecdsa_pattern" ascii //weight: 1
        $x_1_2 = "adesklovers" ascii //weight: 1
        $x_1_3 = "system.privilege.admin" ascii //weight: 1
        $x_1_4 = "doMemPatch" ascii //weight: 1
        $x_1_5 = "KeyGen" ascii //weight: 1
        $x_1_6 = "execMeAsRoot" ascii //weight: 1
        $x_1_7 = "Successfully patched" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

