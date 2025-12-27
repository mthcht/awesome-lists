rule TrojanSpy_AndroidOS_Spynote_C_2147755397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.C!MTB"
        threat_id = "2147755397"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcmf0/c3b5bm90zq/patch" ascii //weight: 1
        $x_1_2 = "system/bin/screencap -p /sdcard/rootSU" ascii //weight: 1
        $x_1_3 = "root@" ascii //weight: 1
        $x_1_4 = "/base.apk" ascii //weight: 1
        $x_1_5 = "has_phone_number!=0 AND (mimetype=? OR mimetype=?)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_K_2147785003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.K!MTB"
        threat_id = "2147785003"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "key_logger_online_start" ascii //weight: 1
        $x_1_2 = "camera_manager_capture" ascii //weight: 1
        $x_1_3 = "Send_Server000" ascii //weight: 1
        $x_1_4 = "spyandroid" ascii //weight: 1
        $x_1_5 = "shell_terminal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_M_2147793794_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.M"
        threat_id = "2147793794"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ArrayDns_Key" ascii //weight: 1
        $x_1_2 = "Contact_server000" ascii //weight: 1
        $x_1_3 = "DesServicScreen" ascii //weight: 1
        $x_1_4 = "upload_file000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_N_2147797463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.N"
        threat_id = "2147797463"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lpackage/name/mmsiaayjumqbsbhwfryjcrurnxukewxoziwjtlo2439" ascii //weight: 2
        $x_2_2 = "/fsjhqxbkkisc24322" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_I_2147799529_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.I"
        threat_id = "2147799529"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Deviceinfo is OK" ascii //weight: 1
        $x_1_2 = "upload&androidid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_O_2147799530_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.O"
        threat_id = "2147799530"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "result=ok&action=getcontact&androidid=" ascii //weight: 1
        $x_1_2 = "&isbank=" ascii //weight: 1
        $x_1_3 = "listnum&androidid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_AXR_2147813545_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.AXR"
        threat_id = "2147813545"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "splash.msicapp.netalfa.RECORD" ascii //weight: 1
        $x_1_2 = "usrgmail" ascii //weight: 1
        $x_1_3 = "ActivSend" ascii //weight: 1
        $x_1_4 = "GetLogs" ascii //weight: 1
        $x_1_5 = "StoragPermissions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_H_2147813995_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.H!MTB"
        threat_id = "2147813995"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 05 3b a7 00 00 b0 56 48 05 03 01 d9 09 06 1f dc 0a 01 02 48 0a 07 0a da 0b 09 4e 91 0b 06 0b b1 96 b0 b6 da 06 06 00 b0 56 93 05 0b 0b db 05 05 01 df 05 05 01 b0 56 94 05 0b 0b b0 56 97 05 06 0a 8d 55 4f 05 04 01 93 05 0b 08 d8 01 01 01}  //weight: 1, accuracy: High
        $x_1_2 = "dalvik/system/DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_D_2147820149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.D!MTB"
        threat_id = "2147820149"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 10 71 10 ?? 01 00 00 0c 01 22 08 2a 00 6e 10 55 00 0a 00 0a 03 6e 10 57 00 0a 00 0a 04 52 95 ?? 00 52 96 ?? 00 07 82 01 b7 76 06 54 00 02 00 6e 10 56 00 08 00 0a 0a 12 0b 32 0a 06 00 71 10 ?? 01 0b 00 0c 01 6e 10 59 00 08 00 6e 10 56 00 08 00 0a 0a 12 30 32 0a 09 00 6e 10 5a 00 08 00 71 10 ?? 01 0b 00 0c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_F_2147822916_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.F!MTB"
        threat_id = "2147822916"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_callr_lsnr_" ascii //weight: 1
        $x_1_2 = "contactedfwanycitationsqhansdcertifiedahobbiesgdeliciousedefendantrwritersrtoddlerlcathedralc3" ascii //weight: 1
        $x_1_3 = "Auto_Click" ascii //weight: 1
        $x_1_4 = "DisablePlayProtect" ascii //weight: 1
        $x_1_5 = "ActivSend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_G_2147824755_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.G!MTB"
        threat_id = "2147824755"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MgetscreamSz" ascii //weight: 1
        $x_1_2 = "RngRover" ascii //weight: 1
        $x_1_3 = "snddataSSMS" ascii //weight: 1
        $x_1_4 = "FlafhStop" ascii //weight: 1
        $x_1_5 = "procekills" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_I_2147829370_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.I!MTB"
        threat_id = "2147829370"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WackMeUpJob" ascii //weight: 1
        $x_1_2 = "isServiceWork" ascii //weight: 1
        $x_1_3 = "activityadm" ascii //weight: 1
        $x_1_4 = "phonixeffect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_U_2147841326_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.U"
        threat_id = "2147841326"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConnectedDownloadManager" ascii //weight: 1
        $x_1_2 = "ygdyeg/systygdyegem/biygdyegn/scrygdyegeencaygdyegp -p ygdyeg/sdcaygdyegrd/roygdyegotSU.ygdyegpng" ascii //weight: 1
        $x_1_3 = "StartServiceGLocation()" ascii //weight: 1
        $x_1_4 = "/chygdyeg/ch2.ygdyegphp?sygdyegsl=" ascii //weight: 1
        $x_2_5 = "Lcom/us/note/C12" ascii //weight: 2
        $x_2_6 = "Lcom/us/note/b" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Spynote_AW_2147851817_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.AW!MTB"
        threat_id = "2147851817"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Config/sys/apps/log/log-" ascii //weight: 1
        $x_1_2 = "enabled_accessibility_services" ascii //weight: 1
        $x_1_3 = "getLaunchIntentForPackage" ascii //weight: 1
        $x_1_4 = "phonixeffect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Spynote_Z_2147956178_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Spynote.Z!MTB"
        threat_id = "2147956178"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Spynote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.shell.myapplication.MainActivity" ascii //weight: 1
        $x_1_2 = "com.cwsapp.view.RnAppLockActivity" ascii //weight: 1
        $x_1_3 = "/common/service/StatusJobService" ascii //weight: 1
        $x_1_4 = "Lcom/shell/common/receiver/MyDeviceAdminReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

