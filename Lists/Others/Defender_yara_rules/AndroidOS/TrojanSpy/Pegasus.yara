rule TrojanSpy_AndroidOS_Pegasus_AS_2147782151_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.AS!MTB"
        threat_id = "2147782151"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pegasus killing process" ascii //weight: 1
        $x_1_2 = "deleteSms-" ascii //weight: 1
        $x_1_3 = "/databases/mmssms.db" ascii //weight: 1
        $x_1_4 = "sms monitor" ascii //weight: 1
        $x_1_5 = "friends.phone_number" ascii //weight: 1
        $x_1_6 = "SMS_LOC_MON" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Pegasus_A_2147786255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.A"
        threat_id = "2147786255"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data/data/com.network.android/.coldboot_init" ascii //weight: 1
        $x_1_2 = "/system/csk \"chmod 711 /mnt/obb/.coldboot_init" ascii //weight: 1
        $x_1_3 = "/adinfo?gi=%s&bf=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Pegasus_C_2147786474_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.C!MTB"
        threat_id = "2147786474"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pegasus" ascii //weight: 1
        $x_2_2 = "export LD_LIBRARY_PATH=/vendor/lib:/system/lib; chmod 777 /data/data/com.whatsapp/databases/" ascii //weight: 2
        $x_2_3 = "/system/csk" ascii //weight: 2
        $x_1_4 = "Binary Sms Monitor" ascii //weight: 1
        $x_1_5 = "chmodOneCommand" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Pegasus_B_2147786539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.B"
        threat_id = "2147786539"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AndroidCallDirectWatcher getCall " ascii //weight: 1
        $x_1_2 = "SmsWatcher start" ascii //weight: 1
        $x_1_3 = "Recorder stopRecording start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Pegasus_D_2147808001_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.D"
        threat_id = "2147808001"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hasProxyBeenCleared" ascii //weight: 1
        $x_1_2 = "NetworkWindowSim" ascii //weight: 1
        $x_1_3 = "networkReciverHandler" ascii //weight: 1
        $x_1_4 = "addRecordFileToProductsDB" ascii //weight: 1
        $x_1_5 = "agentExfiltrationHeader" ascii //weight: 1
        $x_1_6 = "com.network.android" ascii //weight: 1
        $x_1_7 = "AndroidCallDirectWatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Pegasus_D_2147851899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Pegasus.D!MTB"
        threat_id = "2147851899"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Pegasus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/decryptstringmanager" ascii //weight: 1
        $x_1_2 = "net_vtp_call_state_info" ascii //weight: 1
        $x_1_3 = "chmodOneCommand" ascii //weight: 1
        $x_1_4 = "AGENT_EXFILTRATION_HEADER" ascii //weight: 1
        $x_1_5 = "sendDataSmsByManager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

