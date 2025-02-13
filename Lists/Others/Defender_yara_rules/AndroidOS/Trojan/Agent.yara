rule Trojan_AndroidOS_Agent_B_2147744866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Agent.B!MTB"
        threat_id = "2147744866"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 42 23 21 19 00 12 00 21 42 35 20 10 00 48 02 04 00 21 53 94 03 00 03 48 03 05 03 b7 32 8d 22 4f 02 01 00 d8 00 00 01 28 f0 11 01}  //weight: 1, accuracy: High
        $x_1_2 = "encodedFileBytes" ascii //weight: 1
        $x_1_3 = "killProcess" ascii //weight: 1
        $x_1_4 = "writedDexFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Agent_E_2147795073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Agent.E"
        threat_id = "2147795073"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "g/com/sv2$sv2_BR;" ascii //weight: 10
        $x_1_2 = "Cannot send files from the assets folder." ascii //weight: 1
        $x_1_3 = "_postmultipart" ascii //weight: 1
        $x_1_4 = "-deviceinfo.txt" ascii //weight: 1
        $x_1_5 = "stun.sipgate.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Agent_D_2147795443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Agent.D"
        threat_id = "2147795443"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 04 01 2d 0c 00 b0 49 48 04 03 02 d1 95 16 07 dc 07 02 03 48 07 08 07 da 0a 09 4d b1 5a da 09 09 00 b3 a9 b0 09 b0 49 93 04 05 05 d8 04 04 ff b0 49 94 04 05 05 b0 49 97 04 09 07 8d 44 4f 04 06 02 14 04 0f ad 83 00 b3 45 d8 02 02 01 01 a9 28 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Agent_AH_2147805133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Agent.AH"
        threat_id = "2147805133"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lockMeNow" ascii //weight: 1
        $x_1_2 = "CALL_LOG_" ascii //weight: 1
        $x_1_3 = "Installing" ascii //weight: 1
        $x_1_4 = "HIDE ICON NOW" ascii //weight: 1
        $x_1_5 = "BotimLauncherAlias" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Agent_RA_2147818679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Agent.RA!MTB"
        threat_id = "2147818679"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/palimona/ivr_premium/receivers" ascii //weight: 2
        $x_1_2 = "IncomingSmsReceiver" ascii //weight: 1
        $x_1_3 = "OutgoingCallReceiver" ascii //weight: 1
        $x_1_4 = "isAlreadyListening" ascii //weight: 1
        $x_1_5 = "api.app4dw.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

