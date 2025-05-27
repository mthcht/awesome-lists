rule Trojan_AndroidOS_Triada_B_2147745126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.B!MTB"
        threat_id = "2147745126"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clt30/test.jsp" ascii //weight: 1
        $x_1_2 = "echo rg_cmd_end_magic" ascii //weight: 1
        $x_1_3 = "ip.cnkyhg.com/ip.php" ascii //weight: 1
        $x_1_4 = "X_UP_CLIENT_CHANNEL_ID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_C_2147812781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.C!MTB"
        threat_id = "2147812781"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 01 21 73 6e 10 ?? ?? 08 00 0a 04 01 10 01 12 35 32 14 00 34 40 03 00 01 10 48 05 07 02 6e 20 ?? ?? 08 00 0a 06 b7 65 8d 55 4f 05 07 02 d8 02 02 01 d8 00 00 01 28 ed 11 07}  //weight: 2, accuracy: Low
        $x_1_2 = "com/fourqaz/sixwsx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_A_2147824585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.A!xp"
        threat_id = "2147824585"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/app/%s/%s.apk" ascii //weight: 1
        $x_1_2 = "toolbox chattr -iaA %s" ascii //weight: 1
        $x_1_3 = "busybox chattr -iaA %s" ascii //weight: 1
        $x_1_4 = "/data/local/tmp/.localtmptest.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_Triada_D_2147831583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.D!MTB"
        threat_id = "2147831583"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kokddlio" ascii //weight: 1
        $x_1_2 = "/app/dd/appXChannel" ascii //weight: 1
        $x_1_3 = "ddlead/dataUpdate.png" ascii //weight: 1
        $x_1_4 = "RunningTaskInfo" ascii //weight: 1
        $x_1_5 = "getmimetypefromextension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_E_2147833878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.E!MTB"
        threat_id = "2147833878"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rtBtBtReceiver" ascii //weight: 1
        $x_1_2 = "chjieservice" ascii //weight: 1
        $x_1_3 = "test6.log" ascii //weight: 1
        $x_1_4 = "/dev/socket/dog.sock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_W_2147899822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.W"
        threat_id = "2147899822"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/system/bin/daemonnis --auto-daemon &" ascii //weight: 1
        $x_1_2 = "rm /system/bin/daemonnis;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_M_2147901920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.M"
        threat_id = "2147901920"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com.orl.ide.Ss" ascii //weight: 2
        $x_1_2 = "apkdownloadURL" ascii //weight: 1
        $x_1_3 = "delaysxtimesa_first" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Triada_H_2147942303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Triada.H!MTB"
        threat_id = "2147942303"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Triada"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "os.config.ppgl.btcore.devicekey" ascii //weight: 1
        $x_1_2 = "os.config.opp.build.status" ascii //weight: 1
        $x_1_3 = "version_ex_config.dat" ascii //weight: 1
        $x_1_4 = "os.config.opp.build.model" ascii //weight: 1
        $x_1_5 = "com.hwsen.abc.SDK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

