rule Trojan_AndroidOS_Basbanke_B_2147785339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.B"
        threat_id = "2147785339"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/Coy90.html" ascii //weight: 2
        $x_2_2 = "xTelaContinua:coy:aaa" ascii //weight: 2
        $x_2_3 = "Execucoesiniciou" ascii //weight: 2
        $x_2_4 = "AddOverlay_A" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_C_2147795489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.C"
        threat_id = "2147795489"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xAccessibiliMasterzinho" ascii //weight: 2
        $x_2_2 = "startertwo_BR" ascii //weight: 2
        $x_2_3 = "xArmazenaEventoAccess" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_A_2147807726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.A"
        threat_id = "2147807726"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "saddsadsasdads" ascii //weight: 1
        $x_1_2 = "trackggppss" ascii //weight: 1
        $x_1_3 = "wsh_WakeupPhone" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_D_2147833111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.D!MTB"
        threat_id = "2147833111"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smssendertest" ascii //weight: 1
        $x_1_2 = "ifad/nrayanp/ir" ascii //weight: 1
        $x_1_3 = "CurrentCountry" ascii //weight: 1
        $x_1_4 = "FindByMail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_D_2147839692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.D"
        threat_id = "2147839692"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT * FROM favsms Order By id Desc" ascii //weight: 2
        $x_2_2 = "UPDATE CheckFree SET EndCreator='True' WHERE id = 1" ascii //weight: 2
        $x_2_3 = "UrlRegUser" ascii //weight: 2
        $x_2_4 = "lbltxtsms" ascii //weight: 2
        $x_2_5 = "lbliconsms1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_E_2147840141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.E"
        threat_id = "2147840141"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HandleIbk5LinesSmsNoBalance" ascii //weight: 2
        $x_2_2 = "ResumableSub_GetAndSyncLatestMessages" ascii //weight: 2
        $x_2_3 = "deposit-system/api/log.php" ascii //weight: 2
        $x_2_4 = "_sincedatetime" ascii //weight: 2
        $x_2_5 = "_min_parsed_data_fields_for_sync" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_G_2147840795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.G!MTB"
        threat_id = "2147840795"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smssyncservice" ascii //weight: 1
        $x_1_2 = "runDirectly" ascii //weight: 1
        $x_1_3 = "msgbox_result" ascii //weight: 1
        $x_1_4 = "com.k1solutions.deposit.system" ascii //weight: 1
        $x_1_5 = "_bank_number_kbank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_N_2147852337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.N"
        threat_id = "2147852337"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&action=WhatsChecker&operator" ascii //weight: 2
        $x_2_2 = "&action=lastOTP&operator=" ascii //weight: 2
        $x_2_3 = "&action=balance&operator=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_M_2147920428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.M"
        threat_id = "2147920428"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Connect_TO_Server_Broker" ascii //weight: 2
        $x_2_2 = "commands_FromPC" ascii //weight: 2
        $x_2_3 = "Send_Certain_SMS_To_Admin_From_Android" ascii //weight: 2
        $x_2_4 = "_noti_replacement" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Basbanke_A_2147927668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basbanke.A!MTB"
        threat_id = "2147927668"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hide_AppData_Info" ascii //weight: 1
        $x_1_2 = "Get_Device_CallLogs" ascii //weight: 1
        $x_1_3 = "Send_CallPhoneNumber" ascii //weight: 1
        $x_1_4 = "Send_SMSMessage_ToNumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

