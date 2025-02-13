rule Trojan_AndroidOS_ApkLodr_A_2147761882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ApkLodr.A!MTB"
        threat_id = "2147761882"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ApkLodr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 61 70 6b 00 00 00 00 64 61 6c 76 69 6b 2f 73 79 73 74 65 6d 2f 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {55 45 73 44 42 42 51 41 43 41 67 49 41 ?? ?? ?? ?? ?? ?? 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 54 41 41 41 41 51 57 35 6b 63 6d 39 70 5a 45 31 68 62 6d 6c 6d 5a 58 4e 30 4c 6e 68 74 62}  //weight: 1, accuracy: Low
        $x_1_3 = "_Z7loadDexP7_JNIEnvP8_jobject" ascii //weight: 1
        $x_1_4 = "Z8emulatorP7" ascii //weight: 1
        $x_1_5 = "Z10deleteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

