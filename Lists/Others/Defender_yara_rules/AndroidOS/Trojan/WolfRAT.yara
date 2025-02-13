rule Trojan_AndroidOS_WolfRAT_A_2147782816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/WolfRAT.A"
        threat_id = "2147782816"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "WolfRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenRecorder" ascii //weight: 1
        $x_1_2 = "Thread Rec" ascii //weight: 1
        $x_1_3 = "Thread sleep : " ascii //weight: 1
        $x_1_4 = "yy/MM/dd HH:mm:ss" ascii //weight: 1
        $x_1_5 = "dumpsys activity | grep \"Run #\" | grep -v ScreenRecorderActivity | head -n 1" ascii //weight: 1
        $x_1_6 = "com.connect" ascii //weight: 1
        $x_1_7 = "com.whatsapp/.voipcalling.VoipActivityV2" ascii //weight: 1
        $x_1_8 = "com.facebook.orca/com.facebook.rtc.activities.WebrtcIncallFragmentHostActivity" ascii //weight: 1
        $x_1_9 = "jp.naver.line.android/com.linecorp.voip.ui.base.VoIPServiceActivity" ascii //weight: 1
        $x_1_10 = "chkStartRec : open " ascii //weight: 1
        $x_1_11 = "chkStartRec : close " ascii //weight: 1
        $x_1_12 = "com.serenegiant.service.ScreenRecorderService.ACTION_STOP" ascii //weight: 1
        $x_1_13 = "media_projection" ascii //weight: 1
        $x_1_14 = "isNativeRunning err :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

rule Trojan_AndroidOS_WolfRAT_B_2147782875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/WolfRAT.B"
        threat_id = "2147782875"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "WolfRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eyJpc3MiOiIwMDAwMDAwMDEzIiwia2lkIjoiMDAwMDAwMDAxMy0wLUlTSS00MWU2ZjBiNS01MjQwLTQwNmMtYjYyMS01NDNlZWZiYjE0ODEiLCI5YjI2OWYzZDFmNjFlNWZhMzY5NSI6dHJ1ZX0" ascii //weight: 1
        $x_1_2 = "svcws.somtum.today" ascii //weight: 1
        $x_1_3 = "Bots/get_update" ascii //weight: 1
        $x_1_4 = "/Commands/comm_getfunction" ascii //weight: 1
        $x_1_5 = "/Commands/delete_comm" ascii //weight: 1
        $x_1_6 = "/Download/update.apk" ascii //weight: 1
        $x_1_7 = "/delete_file" ascii //weight: 1
        $x_1_8 = "/upload_file" ascii //weight: 1
        $x_1_9 = "/Messages/mess_update" ascii //weight: 1
        $x_1_10 = "/upload-pictures.php?" ascii //weight: 1
        $x_1_11 = "/mnt/sdcard/Download/update.apk" ascii //weight: 1
        $x_1_12 = "/storage/emulated/0/System/Calls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

