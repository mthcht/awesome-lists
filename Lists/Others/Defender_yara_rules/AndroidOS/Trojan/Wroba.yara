rule Trojan_AndroidOS_Wroba_B_2147765889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.B!MTB"
        threat_id = "2147765889"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "com/nh6202006293/activity/MainActivity" ascii //weight: 3
        $x_1_2 = "aHR0cDovLzE4Mi4xNi44Ny4yMDI=" ascii //weight: 1
        $x_1_3 = "content://call_log/calls" ascii //weight: 1
        $x_1_4 = "date desc limit 500" ascii //weight: 1
        $x_1_5 = "DecryptPacketPhon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Wroba_L_2147831759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.L!MTB"
        threat_id = "2147831759"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 17 4c 67 ?? ?? ?? ?? ?? ?? 2f ?? ?? 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 02 6a 7a 00 02 6b 67 00 0b 6c 6f 61 64 4c 69 62 72 61 72 79 00 02 6c 73 00 02 6d 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {3b 00 06 4c 73 2f 6e 69 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 73 49 67 6e 6f 72 69 6e 67 42 61 74 74 65 72 79 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_M_2147835603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.M!MTB"
        threat_id = "2147835603"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 17 4c 67 ?? ?? ?? ?? ?? ?? 2f ?? ?? 41 70 70 6c 69 63 61 74 69 6f 6e 3b 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 00 06 4c 73 2f 6e 69 3b 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f 65 6c 61 70 73 65 64 52 65 61 6c 74 69 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 73 49 67 6e 6f 72 69 6e 67 42 61 74 74 65 72 79 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {63 61 74 69 6f 6e 3b 08 00 2f ?? ?? 41 70 70 6c 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_C_2147837896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.C!MTB"
        threat_id = "2147837896"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/AddSMS.aspx" ascii //weight: 1
        $x_1_2 = "AddBankPwdTask" ascii //weight: 1
        $x_1_3 = "CheckSmsMessages" ascii //weight: 1
        $x_1_4 = "/telwebservicestwo.asmx" ascii //weight: 1
        $x_1_5 = "RootSMS" ascii //weight: 1
        $x_1_6 = "Addbankmessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_N_2147840485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.N!MTB"
        threat_id = "2147840485"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendApps" ascii //weight: 1
        $x_1_2 = "/kbs.php?m=Api&a=" ascii //weight: 1
        $x_1_3 = "isOrderedBroadcast" ascii //weight: 1
        $x_1_4 = "SEMRECEIVER_DATA" ascii //weight: 1
        $x_1_5 = "KR_NHBank.apk" ascii //weight: 1
        $x_1_6 = "changeApk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_D_2147852239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.D!MTB"
        threat_id = "2147852239"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 65 65 70 41 6c 69 76 65 00 74 72 79 20 74 6f 20 6c 6f 63 6b 20 66 69 6c 65 20 22 25 73 22 2e 00 6c 6f 63 6b 20 66 69 6c 65 20 66 61 69 6c 65 64 20 22 25 73 22 2e 00 6c 6f 63 6b 20 66 69 6c 65 20 73 75 63 63 65 73 73 20 22 25 73 22 2e 00 28 29 56 00 2d 6f 00 6f 6e 50 72 6f 63 65 73 73}  //weight: 1, accuracy: High
        $x_1_2 = "lock file success" ascii //weight: 1
        $x_1_3 = "fork child process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_M_2147898982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.M"
        threat_id = "2147898982"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "onProcessDie" ascii //weight: 1
        $x_1_2 = ":Workcco" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_K_2147911610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.K"
        threat_id = "2147911610"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "click-phone-reject" ascii //weight: 2
        $x_2_2 = "tmpOutNumber=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Wroba_AZ_2147924223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Wroba.AZ"
        threat_id = "2147924223"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Wroba"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "last outgoing calllog number=" ascii //weight: 2
        $x_2_2 = "CF_PhoneStateListener" ascii //weight: 2
        $x_2_3 = "TBL_NAME_NUMBERS" ascii //weight: 2
        $x_2_4 = "lockedWhenComing" ascii //weight: 2
        $x_2_5 = "seC/qdtheyt/ydjuhdqB/juBufxedO/YJuBufxedO" ascii //weight: 2
        $x_2_6 = "p3 succeed, Send ForceCallData view=" ascii //weight: 2
        $x_2_7 = "PC_CallRvProc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

