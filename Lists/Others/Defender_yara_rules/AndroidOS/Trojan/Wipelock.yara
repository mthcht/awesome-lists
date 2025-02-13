rule Trojan_AndroidOS_Wipelock_GV_2147786954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wipelock.GV!MTB"
        threat_id = "2147786954"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wipelock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HideAppFromLauncher" ascii //weight: 1
        $x_1_2 = "wipeMemoryCard" ascii //weight: 1
        $x_1_3 = "com/elite/LockScreen" ascii //weight: 1
        $x_1_4 = "isCallfromPasswordScreen" ascii //weight: 1
        $x_1_5 = "content://sms/inbox" ascii //weight: 1
        $x_1_6 = "UninstallAdminDevice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wipelock_A_2147829420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wipelock.A!MTB"
        threat_id = "2147829420"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wipelock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getmimetypefromextension" ascii //weight: 1
        $x_1_2 = "addSMSIntoInbox" ascii //weight: 1
        $x_1_3 = "isCallfromPasswordScreen" ascii //weight: 1
        $x_1_4 = "keepRunningActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

