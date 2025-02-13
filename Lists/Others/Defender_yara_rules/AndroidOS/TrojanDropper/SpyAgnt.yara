rule TrojanDropper_AndroidOS_SpyAgnt_A_2147824572_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/SpyAgnt.A!MTB"
        threat_id = "2147824572"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "SpyAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "of87oaufaldjawdjkw.dex" ascii //weight: 1
        $x_1_2 = "Lib13readAssetFileEP7_JNIEnv" ascii //weight: 1
        $x_1_3 = "call cip.init(Cipher.DECRYPT_MODE, myKey)" ascii //weight: 1
        $x_1_4 = "dalvik/system/DexClassLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

