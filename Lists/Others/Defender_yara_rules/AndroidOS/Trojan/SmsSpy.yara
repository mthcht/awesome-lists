rule Trojan_AndroidOS_SmsSpy_A_2147744717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.A!MTB"
        threat_id = "2147744717"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pay.918ja.com" ascii //weight: 2
        $x_1_2 = "com.dyl.pay.ui.apk" ascii //weight: 1
        $x_1_3 = "sms_pay_list" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_B_2147745615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.B!MTB"
        threat_id = "2147745615"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/zbj/uploadinfo/UploadOutSmsThread;" ascii //weight: 1
        $x_1_2 = "/api_visit.php?number=" ascii //weight: 1
        $x_1_3 = "SmsUploadService" ascii //weight: 1
        $x_1_4 = "uploadContacts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_D_2147745618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.D!MTB"
        threat_id = "2147745618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start moon_send_sms" ascii //weight: 1
        $x_1_2 = "moon_sys_install_app start install apk" ascii //weight: 1
        $x_1_3 = "moon_sys_get_userinfo" ascii //weight: 1
        $x_1_4 = "MONITORSMS" ascii //weight: 1
        $x_1_5 = "aknserver_ptl.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_D_2147745618_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.D!MTB"
        threat_id = "2147745618"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/net/manager/CallUploadManager;" ascii //weight: 1
        $x_1_2 = "/monitor/SmsMonitor;" ascii //weight: 1
        $x_1_3 = "SmsUploadManager response" ascii //weight: 1
        $x_1_4 = "/Android/Sma/Log" ascii //weight: 1
        $x_1_5 = "/mobile/method4" ascii //weight: 1
        $x_1_6 = "/mobile/uploadSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_C_2147745619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.C!MTB"
        threat_id = "2147745619"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Java_com_samsung_appstore6_Masker_getMsg" ascii //weight: 2
        $x_1_2 = "/api_phonebook.php" ascii //weight: 1
        $x_1_3 = "/api_msg.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_C_2147745619_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.C!MTB"
        threat_id = "2147745619"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/samsung/appstore6/PG_SMSObserver;" ascii //weight: 1
        $x_1_2 = "CF_PersonData.java" ascii //weight: 1
        $x_1_3 = "ma2sker" ascii //weight: 1
        $x_1_4 = "getUploadPhonebookXML" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_E_2147752184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.E!MTB"
        threat_id = "2147752184"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6d 5f 73 6d 73 00 6d 5f 64 61 65 6d 6f 6e 73 65 72 76 69 63 65 00 6d 5f 73 6d 73 73 65 72 76 69 63 65 00 6d 5f 73 79 73 69 6e 66 6f}  //weight: 2, accuracy: High
        $x_1_2 = {73 6d 73 70 74 6c 76 00 76 73 5f 66 69 6c 74 65 72 2e 74 78 74}  //weight: 1, accuracy: High
        $x_1_3 = "s/b1/main/main.dat" ascii //weight: 1
        $x_1_4 = "&PhoneInfo=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_E_2147752184_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.E!MTB"
        threat_id = "2147752184"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "interop/ctbok.aspx?id" ascii //weight: 1
        $x_1_2 = "com.soan.sms.delivery" ascii //weight: 1
        $x_1_3 = "gmubeta.g188.net/SecurePortal/servlet" ascii //weight: 1
        $x_1_4 = "XDD@;..70/055/084/078.S]Y^DUBVQSU.C]C.CI^S/QC@H" ascii //weight: 1
        $x_1_5 = "AgencyID.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_A_2147753856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.A"
        threat_id = "2147753856"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&default_dialer_app_name=" ascii //weight: 2
        $x_2_2 = "&default_dialer_package_name=" ascii //weight: 2
        $x_2_3 = "/sound/SoundService" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_A_2147753856_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.A"
        threat_id = "2147753856"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/psiphon3/smsreceived" ascii //weight: 2
        $x_1_2 = "&receiveSMS=true" ascii //weight: 1
        $x_1_3 = "&lastsms&message=" ascii //weight: 1
        $x_1_4 = "Hide=True&androidid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_A_2147753856_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.A"
        threat_id = "2147753856"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4c 63 6f 6d 2f 73 79 73 74 65 6d 2f 73 6d 73 2f [0-6] 2f 53 6d 53 73 65 72 76 65 72}  //weight: 3, accuracy: Low
        $x_3_2 = {4c 63 6f 6d 2f 73 79 73 74 65 6d 2f 73 6d 73 2f [0-6] 2f 53 6d 53 52 65 63 65 69 76 65 72}  //weight: 3, accuracy: Low
        $x_3_3 = "Lcom/sms/tract/SmSserver" ascii //weight: 3
        $x_3_4 = "Lcom/sms/tract/SmSReceiver" ascii //weight: 3
        $x_1_5 = "islj" ascii //weight: 1
        $x_1_6 = "9999-01-15 00:50:00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsSpy_F_2147761955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.F!MTB"
        threat_id = "2147761955"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Camera/?e=1351855869&pay=pasargad" ascii //weight: 1
        $x_1_2 = "://uaioey.ga/MainDomain.txt" ascii //weight: 1
        $x_1_3 = "doInBackground" ascii //weight: 1
        $x_1_4 = "://uaioey.ga/otp.php" ascii //weight: 1
        $x_1_5 = "ir.pardakht.Sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_F_2147761955_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.F!MTB"
        threat_id = "2147761955"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flasz.java" ascii //weight: 1
        $x_1_2 = "FileDownloadListener" ascii //weight: 1
        $x_1_3 = "://app.zjhyt.com/msg/||nimsi:|" ascii //weight: 1
        $x_1_4 = "://down.rhosdn.com/360.apk" ascii //weight: 1
        $x_1_5 = "SENT_SMS_ACTION" ascii //weight: 1
        $x_1_6 = "://tqkjyxgs.com:8080/msg/" ascii //weight: 1
        $x_1_7 = "://ip.cnkyhg.com/ip.php" ascii //weight: 1
        $x_1_8 = "GetAddressByIp" ascii //weight: 1
        $x_1_9 = "checkEmailAddress" ascii //weight: 1
        $x_1_10 = "checkPhoneNum" ascii //weight: 1
        $x_1_11 = "com.sxwz.lovetheater.sms.config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_H_2147810332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.H"
        threat_id = "2147810332"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "29209dj20d392j3dk0jirjf0i3jf203" ascii //weight: 1
        $x_1_2 = "fullsms_caco333" ascii //weight: 1
        $x_1_3 = "ResumableSub_Service_Start" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_H_2147830295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.H!MTB"
        threat_id = "2147830295"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FeeSmsService" ascii //weight: 1
        $x_1_2 = "DeleteStoreSMS" ascii //weight: 1
        $x_1_3 = "StartSmsService" ascii //weight: 1
        $x_1_4 = "send_self_sms" ascii //weight: 1
        $x_1_5 = "start_browser" ascii //weight: 1
        $x_1_6 = "smsReceiverProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_D_2147836256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.D"
        threat_id = "2147836256"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/pointrewardas.co.in/api/" ascii //weight: 2
        $x_2_2 = "prefNameUSERNAME" ascii //weight: 2
        $x_2_3 = "com.example.newmultihdfcallrdsmbbgnnmjhello" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_L_2147838098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.L"
        threat_id = "2147838098"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dekhmessage" ascii //weight: 2
        $x_2_2 = "exampleno nunber" ascii //weight: 2
        $x_2_3 = "com.my.update" ascii //weight: 2
        $x_2_4 = "mycomplainquery.in/api" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_M_2147842542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.M"
        threat_id = "2147842542"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&text=Berhasil Kirim SMS ke :" ascii //weight: 2
        $x_2_2 = ", Isi Pesan :" ascii //weight: 2
        $x_2_3 = "6281383115776" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_M_2147842542_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.M"
        threat_id = "2147842542"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "&text=*Kentut Hydro Coco * %0A%0A*Kentut*" ascii //weight: 2
        $x_2_2 = "Telepon Hydro Coco" ascii //weight: 2
        $x_2_3 = "appjava/ReceiveSms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_N_2147842919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.N!MTB"
        threat_id = "2147842919"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/allservicecenter/android/MainActivity" ascii //weight: 1
        $x_2_2 = "com/example/android/MainActivity" ascii //weight: 2
        $x_2_3 = "MsReceiver" ascii //weight: 2
        $x_1_4 = "allPermissionsGranted" ascii //weight: 1
        $x_1_5 = "sendData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_SmsSpy_O_2147847742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.O"
        threat_id = "2147847742"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ratsms.php?phone=" ascii //weight: 2
        $x_2_2 = "erroeererewrwerwer" ascii //weight: 2
        $x_2_3 = "siqe/holo/connect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SmsSpy_AH_2147921647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSpy.AH"
        threat_id = "2147921647"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "secondpageofgreed" ascii //weight: 2
        $x_2_2 = "checkSmsPermissionOnClick" ascii //weight: 2
        $x_2_3 = "deep84Mob021ile78Reg6ister895ed054Suc89cess9fully2024" ascii //weight: 2
        $x_2_4 = "action=android&site=%s&sender=%s&message=%s" ascii //weight: 2
        $x_2_5 = "royal/developer/myapplicatioq" ascii //weight: 2
        $x_2_6 = "myapplicatioo/ReceiveSMS" ascii //weight: 2
        $x_2_7 = "ReceiveSMS$$ExternalSyntheticApiModelOutline0" ascii //weight: 2
        $x_2_8 = "apk-sms-arguments01" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

