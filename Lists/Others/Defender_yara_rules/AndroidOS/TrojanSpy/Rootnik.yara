rule TrojanSpy_AndroidOS_Rootnik_YA_2147757465_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Rootnik.YA!MTB"
        threat_id = "2147757465"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "statsevent.clickmsummer.com" ascii //weight: 1
        $x_1_2 = "genRootProcess exeCmd=" ascii //weight: 1
        $x_1_3 = "&osRuntime=" ascii //weight: 1
        $x_1_4 = "system/app/USBUsageServiceInfo.apk" ascii //weight: 1
        $x_1_5 = "&rebootCount=" ascii //weight: 1
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-21] 2f 4d 6f 62 69 4c 6f 67 2f 6c 6f 67 2f 61 64 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

