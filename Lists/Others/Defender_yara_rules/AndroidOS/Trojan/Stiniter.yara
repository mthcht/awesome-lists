rule Trojan_AndroidOS_Stiniter_A_2147655366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stiniter.A"
        threat_id = "2147655366"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--- MyBroadcastReceiver onReceive ---" ascii //weight: 1
        $x_1_2 = "AndoidService.java" ascii //weight: 1
        $x_1_3 = "%Thread-------run----------break------" ascii //weight: 1
        $x_1_4 = "Start AndoidService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Stiniter_A_2147655366_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stiniter.A"
        threat_id = "2147655366"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--- onCreate GoogleUpdateService ---" ascii //weight: 1
        $x_1_2 = "---start rootSatae" ascii //weight: 1
        $x_1_3 = "--- error ---" ascii //weight: 1
        $x_1_4 = "/system/bin/keeper" ascii //weight: 1
        $x_1_5 = "GBroadcastReceiver.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Stiniter_A_2147655366_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Stiniter.A"
        threat_id = "2147655366"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Stiniter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "</MobileInfo>" ascii //weight: 1
        $x_1_2 = "Has_Key_Released" ascii //weight: 1
        $x_1_3 = ";chmod 777 /data/data/android.gdwsklzz.com/googlemessage.apk" ascii //weight: 1
        $x_1_4 = ";chmod 777 /data/data/android.gdwsklzz.com/googleservice.apk" ascii //weight: 1
        $x_1_5 = "---fail writedatainfo" ascii //weight: 1
        $x_1_6 = "---start rootSatae" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

