rule TrojanDropper_AndroidOS_JokerDropper_A_2147814948_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/JokerDropper.A"
        threat_id = "2147814948"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "JokerDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "xn3o.oss-accelerate.aliyuncs.com" ascii //weight: 20
        $x_3_2 = "loadClass" ascii //weight: 3
        $x_3_3 = "dalvik.system.DexClassLoader" ascii //weight: 3
        $x_3_4 = "dalvik-cache" ascii //weight: 3
        $x_5_5 = "com.xn3o" ascii //weight: 5
        $x_3_6 = "DexFileName" ascii //weight: 3
        $x_3_7 = "java.lang.ClassLoader" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

