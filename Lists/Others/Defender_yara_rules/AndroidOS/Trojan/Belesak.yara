rule Trojan_AndroidOS_Belesak_A_2147744661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Belesak.A!MTB"
        threat_id = "2147744661"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Belesak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/rmwr.sh" ascii //weight: 1
        $x_1_2 = "IPC_FILEDATA_DUMP" ascii //weight: 1
        $x_1_3 = "/system/etc/xrebuild.sh" ascii //weight: 1
        $x_1_4 = "IPC_APPDATA_SCREENSHOT" ascii //weight: 1
        $x_1_5 = "IPC_COMMAND_PTRACE_HOOK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

