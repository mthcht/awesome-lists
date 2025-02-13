rule HackTool_AndroidOS_Mesploit_A_2147750963_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Mesploit.A"
        threat_id = "2147750963"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Mesploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/metasploit/stage/" ascii //weight: 2
        $x_2_2 = "/Payload;" ascii //weight: 2
        $x_1_3 = {2e 64 65 78 00 04 2e 6a 61 72 00 01 2f 00 01 3a}  //weight: 1, accuracy: High
        $x_1_4 = {70 61 79 6c 6f 61 64 2e 64 65 78 00 0b 70 61 79 6c 6f 61 64 2e 6a 61 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_AndroidOS_Mesploit_B_2147752650_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Mesploit.B!MTB"
        threat_id = "2147752650"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Mesploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/metasploit/stage/MainActivity" ascii //weight: 2
        $x_1_2 = "stage/Payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Mesploit_C_2147782933_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Mesploit.C"
        threat_id = "2147782933"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Mesploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tcp://87.19.73.8:24079" ascii //weight: 1
        $x_1_2 = {2e 64 65 78 00 0e 2e [0-32] 00 04 2e 6a 61 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "createNewFile" ascii //weight: 1
        $x_1_4 = "DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_AndroidOS_Mesploit_C_2147846763_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:AndroidOS/Mesploit.C!MTB"
        threat_id = "2147846763"
        type = "HackTool"
        platform = "AndroidOS: Android operating system"
        family = "Mesploit"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ClientApplicationSplittedShell" ascii //weight: 1
        $x_5_2 = "SO-8859-1" ascii //weight: 5
        $x_1_3 = "getclipdata" ascii //weight: 1
        $x_1_4 = "getClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

