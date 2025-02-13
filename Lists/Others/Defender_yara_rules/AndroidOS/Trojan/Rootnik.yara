rule Trojan_AndroidOS_Rootnik_A_2147783540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.A"
        threat_id = "2147783540"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data/local/zen/inject.apk" ascii //weight: 1
        $x_1_2 = "SuReceiver -- " ascii //weight: 1
        $x_1_3 = "copy libworm_ku" ascii //weight: 1
        $x_1_4 = "hasSuRoot" ascii //weight: 1
        $x_1_5 = "Inject main pid" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Rootnik_B_2147812199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.B!xp"
        threat_id = "2147812199"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/.android/.system/.cz/.op/package.properties" ascii //weight: 1
        $x_1_2 = "/HealthRecord/test.log" ascii //weight: 1
        $x_1_3 = "/sdcard/.rid" ascii //weight: 1
        $x_1_4 = "Data/.rootgenius" ascii //weight: 1
        $x_1_5 = "com.womi.activity." ascii //weight: 1
        $x_1_6 = "//zfandcz.alphafalab.com:8585" ascii //weight: 1
        $x_1_7 = "//offer2.joymedia.mobi/index.php?r=api/offerclick&offer_id=23916&aff_id" ascii //weight: 1
        $x_1_8 = {3a 2f 2f 71 64 63 75 30 31 2e 62 61 69 64 75 70 63 73 2e 63 6f 6d 2f 66 69 6c 65 2f [0-48] 3f 62 6b 74 3d}  //weight: 1, accuracy: Low
        $x_1_9 = "com.iSecurityCamClient-1.apk" ascii //weight: 1
        $x_1_10 = "//push.dengandroid.com/getrootjarinfo" ascii //weight: 1
        $x_1_11 = {6d 6f 75 6e 74 20 2d 6f 20 72 65 6d 6f 75 6e 74 2c 72 77 20 2f 73 79 73 74 65 6d [0-2] 65 63 68 6f 20 72 6f 6f 74 65 64 20 3e 20 2f 73 79 73 74 65 6d 2f 72 6f 6f 74 65 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_Rootnik_C_2147822364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.C!xp"
        threat_id = "2147822364"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/files/%s%d.jar" ascii //weight: 1
        $x_1_2 = "/syetm/lib:/vendor/lib" ascii //weight: 1
        $x_1_3 = "%s/%s%d.dex" ascii //weight: 1
        $x_1_4 = "libSdkImport.so" ascii //weight: 1
        $x_1_5 = {66 67 20 70 61 74 68 3a 25 73 00 2f 73 79 73 74 65 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Rootnik_D_2147828874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.D!MTB"
        threat_id = "2147828874"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system/app/usbusageserviceinfo.apk" ascii //weight: 1
        $x_1_2 = "&rebootcount=" ascii //weight: 1
        $x_1_3 = "&osruntime=" ascii //weight: 1
        $x_1_4 = "tictop.phototovideomaker2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rootnik_B_2147832693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.B!MTB"
        threat_id = "2147832693"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 6f 63 6b 4f 70 65 72 61 74 69 6f 6e 00 28 4c ?? 61 76 61}  //weight: 1, accuracy: Low
        $x_1_2 = {72 74 73 65 72 76 69 63 65 20 2d 2d 75 73 65 72 20 30 20 2d 61 ?? ?? 73 00 61 6d 20 73 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Rootnik_E_2147843816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Rootnik.E"
        threat_id = "2147843816"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xx Upload Device to server start" ascii //weight: 2
        $x_2_2 = "/mnt/extsdcard/android_ad_trace.log" ascii //weight: 2
        $x_2_3 = "sub_jc_v02.apk" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

