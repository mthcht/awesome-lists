rule HackTool_MacOS_SuspMalAgent_X_2147948862_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/SuspMalAgent.X"
        threat_id = "2147948862"
        type = "HackTool"
        platform = "MacOS: "
        family = "SuspMalAgent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "klist 2>/dev/null | awk '/Principal/" ascii //weight: 10
        $x_10_2 = "system_profiler SPHardwareDataType 2>/dev/null | awk '/Processor Name" ascii //weight: 10
        $x_10_3 = "md5 | xxd -r -p | base64" ascii //weight: 10
        $x_10_4 = "ifconfig en0 | awk '/ether" ascii //weight: 10
        $x_10_5 = "chmod 755" ascii //weight: 10
        $x_1_6 = "uuidgen" ascii //weight: 1
        $x_1_7 = "echo" ascii //weight: 1
        $x_1_8 = "sendRequest" ascii //weight: 1
        $x_1_9 = "POST" ascii //weight: 1
        $x_1_10 = "IOPlatformExpertDevice" ascii //weight: 1
        $x_1_11 = "IOPlatformSerialNumber" ascii //weight: 1
        $x_1_12 = "IOPlatformUUID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

