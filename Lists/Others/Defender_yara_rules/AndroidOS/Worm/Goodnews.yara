rule Worm_AndroidOS_Goodnews_A_2147772067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Goodnews.A!MTB"
        threat_id = "2147772067"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Goodnews"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "myWhatsappContactsNo" ascii //weight: 1
        $x_1_2 = "aHR0cDovL3RpbnkuY2M" ascii //weight: 1
        $x_1_3 = "com.see.cowinhelp" ascii //weight: 1
        $x_1_4 = "CoWIN Registration Process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_AndroidOS_Goodnews_B_2147779220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Goodnews.B!MTB"
        threat_id = "2147779220"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Goodnews"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/chodukaka/isporban" ascii //weight: 1
        $x_1_2 = "StartAppAd" ascii //weight: 1
        $x_1_3 = "getSubId" ascii //weight: 1
        $x_1_4 = "You need to click on Ad to Continue." ascii //weight: 1
        $x_1_5 = "To start Tiktok, follow next steps" ascii //weight: 1
        $x_1_6 = "Click on Next Button to continue" ascii //weight: 1
        $x_1_7 = "http://tiny.cc/Tiktok-Pro" ascii //weight: 1
        $x_1_8 = "Share this APP on Whatsapp groups 10 Times.\\nto Start Tiktok." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Worm_AndroidOS_Goodnews_C_2147780496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Goodnews.C!MTB"
        threat_id = "2147780496"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Goodnews"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Getting details...." ascii //weight: 1
        $x_1_2 = "Click on Ad and install app to Continue!!" ascii //weight: 1
        $x_1_3 = "Please Click on AD to and Install app to continue" ascii //weight: 1
        $x_1_4 = "//tiny.cc/COVID-VACCINE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_AndroidOS_Goodnews_GV_2147785362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:AndroidOS/Goodnews.GV!MTB"
        threat_id = "2147785362"
        type = "Worm"
        platform = "AndroidOS: Android operating system"
        family = "Goodnews"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getActiveSubscriptionInfoList" ascii //weight: 1
        $x_1_2 = "has_phone_number" ascii //weight: 1
        $x_1_3 = "getSubId" ascii //weight: 1
        $x_1_4 = "StartAppAd" ascii //weight: 1
        $x_1_5 = "To start Offers, follow next steps..." ascii //weight: 1
        $x_1_6 = "CoWIN Registration Process" ascii //weight: 1
        $x_1_7 = "Click on Ad and install app from Ad to Continue" ascii //weight: 1
        $x_1_8 = "https://tiny.cc/Pubg-INDIA" ascii //weight: 1
        $x_1_9 = "Need Permission to start app!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

