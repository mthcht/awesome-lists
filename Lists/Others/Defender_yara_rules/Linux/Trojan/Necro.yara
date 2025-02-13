rule Trojan_Linux_Necro_A_2147759463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Necro.A!MTB"
        threat_id = "2147759463"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Necro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 48 78 44 00 68 00 68 d0 e9 0a 40 84 42 52 d0 33 48 df f8 c8 a0 78 44 df f8 bc b0 fa 44 05 68 fb 44 2c 48 78 44 07 68}  //weight: 1, accuracy: High
        $x_1_2 = "a.antlauncher.com" ascii //weight: 1
        $x_1_3 = "/data/.ant_checkper_dir/keystore" ascii //weight: 1
        $x_1_4 = "InjectInterface" ascii //weight: 1
        $x_1_5 = "/mnt/sdcard/Download/kingroot.apk.tmp" ascii //weight: 1
        $x_1_6 = "g_antResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

