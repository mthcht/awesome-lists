rule Ransom_AndroidOS_SimpLock_A_2147687848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SimpLock.A"
        threat_id = "2147687848"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SimpLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/simplelocker/DecryptService" ascii //weight: 1
        $x_1_2 = "jndlasf074hr" ascii //weight: 1
        $x_1_3 = "DISABLE_LOCKER" ascii //weight: 1
        $x_1_4 = "FILES_WAS_ENCRYPTED" ascii //weight: 1
        $x_1_5 = "AES/CBC/PKCS7Padding" ascii //weight: 1
        $x_1_6 = "locker check" ascii //weight: 1
        $x_1_7 = "WakeLock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_AndroidOS_SimpLock_B_2147687849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SimpLock.B"
        threat_id = "2147687849"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SimpLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//ebuha4a.net/keys/" ascii //weight: 1
        $x_1_2 = "CardSvSt.java" ascii //weight: 1
        $x_1_3 = "Landroid/os/PowerManager$WakeLock;" ascii //weight: 1
        $x_1_4 = "Lmy/sharaga/locker/BuildConfig;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_AndroidOS_SimpLock_C_2147706646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SimpLock.C"
        threat_id = "2147706646"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SimpLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//ebuha4a.net/keys/" ascii //weight: 1
        $x_1_2 = "Landroid/os/PowerManager$WakeLock;" ascii //weight: 1
        $x_1_3 = "genkey" ascii //weight: 1
        $x_1_4 = "WakefulBroadcastReceiver.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

