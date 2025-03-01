rule Trojan_AndroidOS_FakeSpy_YA_2147759366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeSpy.YA!MTB"
        threat_id = "2147759366"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "servlet/AppInfos" ascii //weight: 1
        $x_1_2 = "servlet/GetMessage2" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f [0-16] 2e 63 6c 75 62}  //weight: 1, accuracy: Low
        $x_1_4 = "sdcard/new.apk" ascii //weight: 1
        $x_1_5 = "Emulator\") == -1" ascii //weight: 1
        $x_1_6 = "mybank" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

