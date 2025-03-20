rule Trojan_AndroidOS_Rewardsteal_A_2147839056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.A"
        threat_id = "2147839056"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rewards/Restarter;" ascii //weight: 1
        $x_1_2 = "Month must be below 12" ascii //weight: 1
        $x_1_3 = "CVV must be of 3 digits." ascii //weight: 1
        $x_1_4 = "@lucky.com" ascii //weight: 1
        $x_1_5 = "rewards/YourService;" ascii //weight: 1
        $x_1_6 = "Year must be less than 2010." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_B_2147841196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.B"
        threat_id = "2147841196"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "submitContactMsgData" ascii //weight: 2
        $x_2_2 = "GetMsgAndContactActivity" ascii //weight: 2
        $x_2_3 = "SMSreceiverNew" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_C_2147841524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.C"
        threat_id = "2147841524"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "canarra545-default-rtdb.firebaseio.com/" ascii //weight: 1
        $x_1_2 = "Please Wait 24h" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_C_2147841524_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.C"
        threat_id = "2147841524"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SEND_SMS_PERMISSION_REQUEST_CODE" ascii //weight: 2
        $x_2_2 = "Card CVV is Required !" ascii //weight: 2
        $x_2_3 = "/root/api/user/sms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_P_2147842585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.P"
        threat_id = "2147842585"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/kkcibil/" ascii //weight: 1
        $x_1_2 = "randumOTP" ascii //weight: 1
        $x_1_3 = "Redeem Successful after 24 hours" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_Q_2147845597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.Q"
        threat_id = "2147845597"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.example.icicibank" ascii //weight: 1
        $x_1_2 = "message  not send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_Q_2147845597_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.Q"
        threat_id = "2147845597"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "web/api/user/sms" ascii //weight: 2
        $x_2_2 = "api/user/step1" ascii //weight: 2
        $x_2_3 = "TqActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_M_2147847829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.M"
        threat_id = "2147847829"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Filled_Hai" ascii //weight: 2
        $x_2_2 = "DATA_USER_NOW" ascii //weight: 2
        $x_2_3 = "send_filtered_sms" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_M_2147847829_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.M"
        threat_id = "2147847829"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "welcome_to_rewards_points_ner_banking_login" ascii //weight: 1
        $x_1_2 = "registerd_mobile_no_customer_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_N_2147852336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.N"
        threat_id = "2147852336"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HarmfulAppReceiver" ascii //weight: 2
        $x_2_2 = "paka/po/Thank" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_N_2147852336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.N"
        threat_id = "2147852336"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "expiry should be atleast 20233" ascii //weight: 2
        $x_1_2 = "Debit card not corrected" ascii //weight: 1
        $x_1_3 = "FourthPagem(debit=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_L_2147852730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.L"
        threat_id = "2147852730"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Card Holder name is Required !" ascii //weight: 1
        $x_2_2 = "com.Rewards.brother" ascii //weight: 2
        $x_1_3 = "Card CVV is Required !" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_L_2147852730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.L"
        threat_id = "2147852730"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://makewinlove.in/" ascii //weight: 1
        $x_1_2 = "Card CVV is Required !" ascii //weight: 1
        $x_1_3 = "Lcom/supercell/clashofclan/TqActivity;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_I_2147852734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.I"
        threat_id = "2147852734"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "googleprotect/ThirdActivity" ascii //weight: 2
        $x_2_2 = "/api/user/step1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_R_2147853153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.R"
        threat_id = "2147853153"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/HDFC_REWARD_App2" ascii //weight: 2
        $x_2_2 = "expiry should be atleast 20233" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_S_2147888195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.S"
        threat_id = "2147888195"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SELECT * FROM SmsLog WHERE TimeStamp = ?" ascii //weight: 2
        $x_2_2 = "CREATE TABLE SmsLog (SmsId TEXT, SmsAddress TEXT,SmsBody TEXT,SmsDateTime TEXT,TimeStamp TEXT)" ascii //weight: 2
        $x_2_3 = "reward2/rewardscreen" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_X_2147890029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.X"
        threat_id = "2147890029"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SMS_API/set_sms_data.php" ascii //weight: 2
        $x_2_2 = "set_user_collector_data.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AS_2147891387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AS"
        threat_id = "2147891387"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PermisiioneRequest" ascii //weight: 2
        $x_2_2 = "create table users (id integer primary key,serverid text)" ascii //weight: 2
        $x_2_3 = "ActivityGkeyboardBinding" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AT_2147894751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AT"
        threat_id = "2147894751"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/api/user/step2" ascii //weight: 2
        $x_2_2 = "digitalposter/PersonalActivity" ascii //weight: 2
        $x_2_3 = "edgecreditsapp.com/api" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AI_2147894752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AI"
        threat_id = "2147894752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Enter Years Upto 2033" ascii //weight: 2
        $x_2_2 = "hdfcofferss/HomeActivity" ascii //weight: 2
        $x_2_3 = "Enter Month From 01-12" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_G_2147895735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.G"
        threat_id = "2147895735"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Well I can't do anything untill you permit me" ascii //weight: 2
        $x_1_2 = "mpin1_box" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_K_2147896293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.K"
        threat_id = "2147896293"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please enter Your CVV No" ascii //weight: 1
        $x_1_2 = "Please enter Your Expiry" ascii //weight: 1
        $x_1_3 = "kmdksamdlkmsalkd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_D_2147896815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.D"
        threat_id = "2147896815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "This Field requires 16 digit" ascii //weight: 2
        $x_2_2 = "PermisiioneRequest" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_D_2147896815_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.D"
        threat_id = "2147896815"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/icici/otp/MainActivity$bindWeb$2" ascii //weight: 1
        $x_1_2 = "let-FormActivity$fetchSMSMessages$1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_T_2147899820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.T"
        threat_id = "2147899820"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "isCreditCardValid$passesLuhnAlgorithm" ascii //weight: 1
        $x_1_2 = "access$navigateToTextScreenAfterDelay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_E_2147899914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.E"
        threat_id = "2147899914"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ActivityCongraBinding" ascii //weight: 2
        $x_2_2 = "sendSmsDataToApi" ascii //weight: 2
        $x_2_3 = "navigateToTextScreenAfterDelay" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_J_2147908491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.J"
        threat_id = "2147908491"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "induscard/PleaseWaitActivity" ascii //weight: 2
        $x_2_2 = "xyz/api/messege.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AD_2147909153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AD"
        threat_id = "2147909153"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "navigateToInfoActivityIfPermissionsGranted" ascii //weight: 2
        $x_2_2 = "p3napps2/SuccessActivity" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AX_2147911033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AX"
        threat_id = "2147911033"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "startSmsForwardingService" ascii //weight: 2
        $x_2_2 = "appkkffrrdd/SmsRepository" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_U_2147913371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.U"
        threat_id = "2147913371"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "pushSmsDataToFirebase" ascii //weight: 2
        $x_2_2 = "saveEndTimePlus72Hours" ascii //weight: 2
        $x_2_3 = "validatePhoneNumberAndSubmit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_KJ_2147914251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.KJ"
        threat_id = "2147914251"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "isRECEVEper" ascii //weight: 2
        $x_2_2 = "MessageResever" ascii //weight: 2
        $x_2_3 = "isSENDper" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AJ_2147914252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AJ"
        threat_id = "2147914252"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ask_to_Ignore_battery_optimisations" ascii //weight: 2
        $x_2_2 = "DATA_USER_NOW" ascii //weight: 2
        $x_2_3 = "PostDataNodeCard" ascii //weight: 2
        $x_2_4 = "GetInBoxMSG_Filter_spent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_F_2147914274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.F"
        threat_id = "2147914274"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.sms.appkkffrrdd" ascii //weight: 1
        $x_1_2 = "SMS saved successfully to the server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_W_2147914275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.W"
        threat_id = "2147914275"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://unplumb-quarters.000webhostapp.com" ascii //weight: 1
        $x_1_2 = "My_Application.app.main" ascii //weight: 1
        $x_1_3 = "Failed to read SMS!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AV_2147914622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AV"
        threat_id = "2147914622"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "kkbk.in/look/" ascii //weight: 2
        $x_2_2 = "sbi/bank/MainActivity2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_Z_2147914852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.Z"
        threat_id = "2147914852"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sbisms2new/Chm3k" ascii //weight: 2
        $x_2_2 = "Aman-sms-1boxsbi" ascii //weight: 2
        $x_2_3 = "sbisms2new/ParkAc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_HT_2147915737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.HT"
        threat_id = "2147915737"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please fill PASSWORD" ascii //weight: 1
        $x_1_2 = "Please fill expary date" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_HT_2147915737_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.HT"
        threat_id = "2147915737"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please Enter Available Limit of Card" ascii //weight: 1
        $x_1_2 = "insertMsgdata: massage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_FT_2147915740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.FT"
        threat_id = "2147915740"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Phone OR SMS permission is not granted" ascii //weight: 1
        $x_1_2 = "SMS SAVE TO PANE :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_FT_2147915740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.FT"
        threat_id = "2147915740"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "idfc-4f54a-default-rtdb.firebaseio.com" ascii //weight: 1
        $x_1_2 = "student7011.github.io/idf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_O_2147916236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.O"
        threat_id = "2147916236"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "generateAlphanumericWord" ascii //weight: 2
        $x_2_2 = "insertMsgdata: massage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AF_2147916914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AF"
        threat_id = "2147916914"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "crdavalibled" ascii //weight: 2
        $x_2_2 = "speratemirgdcard" ascii //weight: 2
        $x_2_3 = "codeindusnew/Sucessful" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_PR_2147919238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.PR"
        threat_id = "2147919238"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "beta-carotene.000webhostapp.com/" ascii //weight: 1
        $x_1_2 = "com.exa.hhkhkhkhk.jhkhkhkhk.jhkhkhkhkhk.mple.testttttt" ascii //weight: 1
        $x_1_3 = "mWebw!!.getSettings()" ascii //weight: 1
        $x_1_4 = "S1m2s3R4e5c6jksdfhksdhkfhkshfe7i8v9e0r" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_FH_2147919246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.FH"
        threat_id = "2147919246"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "axscard.onrender.com" ascii //weight: 1
        $x_1_2 = "Lcom/gurujifinder/mjpro" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_V_2147920429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.V"
        threat_id = "2147920429"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "atm 4 digit is required" ascii //weight: 2
        $x_2_2 = "DebitCardInputMask" ascii //weight: 2
        $x_2_3 = "CVV 3 digit required" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AG_2147921644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AG"
        threat_id = "2147921644"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "thisaub/MyDeviceAdminReceiver" ascii //weight: 2
        $x_2_2 = "Only 10 digit of phone number are allowed !" ascii //weight: 2
        $x_2_3 = "Only 2 charectors are allowed !" ascii //weight: 2
        $x_2_4 = "Attempting to hide app icon:" ascii //weight: 2
        $x_2_5 = "complainsolutions.in/" ascii //weight: 2
        $x_2_6 = "Android security service are running" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AM_2147921649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AM"
        threat_id = "2147921649"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "onrender.com/dataC" ascii //weight: 2
        $x_2_2 = "PostDataNodeCard" ascii //weight: 2
        $x_2_3 = "Check_if_internet_simple" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AE_2147921650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AE"
        threat_id = "2147921650"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Please enter both mobile number and MPIN" ascii //weight: 2
        $x_2_2 = "SMS permissions already granted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AQ_2147924224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AQ"
        threat_id = "2147924224"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendSmsDataToApi" ascii //weight: 2
        $x_2_2 = "itsic/Urespons" ascii //weight: 2
        $x_2_3 = "itsic/Servic" ascii //weight: 2
        $x_2_4 = "com/lod/aa/User" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_QP_2147926436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.QP"
        threat_id = "2147926436"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "isCheckingForSms" ascii //weight: 2
        $x_2_2 = "startSmsChecking" ascii //weight: 2
        $x_2_3 = "setSmsSubmitted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_CY_2147928918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.CY"
        threat_id = "2147928918"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "carrentpricing" ascii //weight: 2
        $x_2_2 = "mobile_api_level" ascii //weight: 2
        $x_2_3 = "german/SentReceiver" ascii //weight: 2
        $x_2_4 = "DomainUpdateReceiver" ascii //weight: 2
        $x_2_5 = "subscription info is null on getSimNumbers" ascii //weight: 2
        $x_2_6 = "aboutuspagebookpage" ascii //weight: 2
        $x_2_7 = "contactdetailsbookpage" ascii //weight: 2
        $x_2_8 = "descriptionpagebookpage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AO_2147934499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AO"
        threat_id = "2147934499"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "system/bg/DeliveredReceiver" ascii //weight: 2
        $x_2_2 = "secure/system/NoInternetActivity" ascii //weight: 2
        $x_2_3 = "billpoggybank" ascii //weight: 2
        $x_2_4 = "intbanbillcode" ascii //weight: 2
        $x_2_5 = "shikaacode" ascii //weight: 2
        $x_2_6 = "FrontServices/ExpiryDateInputMask" ascii //weight: 2
        $x_2_7 = "comaxismobilesaleves23" ascii //weight: 2
        $x_2_8 = "FrontServices/DebitCardInputMask" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_AndroidOS_Rewardsteal_AL_2147936553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rewardsteal.AL"
        threat_id = "2147936553"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rewardsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "omantelprize/CardPayment2" ascii //weight: 2
        $x_2_2 = "SmsService::WakeLock" ascii //weight: 2
        $x_2_3 = "omantelprize/ServiceRestarterBroadcastReceiver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

