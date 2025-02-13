rule HackTool_Linux_Keylogger_A_2147762820_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Keylogger.A!MTB"
        threat_id = "2147762820"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Keylogger"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://localhost:3333/upload" ascii //weight: 1
        $x_1_2 = "/tmp/key.log" ascii //weight: 1
        $x_1_3 = "pyx_pf_9keylogger_sendFiles" ascii //weight: 1
        $x_1_4 = "pyx_pf_9keylogger_2capturar" ascii //weight: 1
        $x_1_5 = "keylogger.py" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

