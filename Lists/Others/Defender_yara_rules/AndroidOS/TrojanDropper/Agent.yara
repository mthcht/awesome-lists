rule TrojanDropper_AndroidOS_Agent_B_2147745125_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Agent.B!MTB"
        threat_id = "2147745125"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 01 6e 10 ?? 00 01 00 6e 10 ?? 00 02 00 0c 01 21 12 35 20 13 00 48 02 01 00 d7 22 ff 00 8d 22 4f 02 01 00 d8 00 00 01 28 f4 6e 10 ?? 00 05 00 6e 10 ?? 00 02 00 28 e9 07 10 28 cd}  //weight: 1, accuracy: Low
        $x_1_2 = "getClassLoader" ascii //weight: 1
        $x_1_3 = "nativeLibraryDir" ascii //weight: 1
        $x_1_4 = "setAccessible" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Agent_D_2147745616_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Agent.D!MTB"
        threat_id = "2147745616"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 20 98 20 8d 20 02 48 34 73 49 41 41 41 41 41 41 41 41 41 4f 53 39 65 58 78 55 31 64 30 2f 66 75 36 64 4a 5a 4d 46 4d 69 45 42 6b 6a 44 67 5a 41 45 6e 42 48 44 43 31 71 44 55 44 70 4d 51 41 6b 45 64 43 57 4a 55 4e 44 4f 51 77 49 51 31 51 73 44 67 30 6f 5a 4e 63 55 45 6e 43 64 41 73 67 47 4f 31 66 53 4a 75 73 59 56 2b 62 51 74 39 59 72 57 74 74 57 70 6e 78 4c 61 75 54 79 65 4a 45 55 53 30 34 31 4b 7a 35}  //weight: 1, accuracy: High
        $x_1_2 = "/at.so" ascii //weight: 1
        $x_1_3 = "V17120101Aj1arso" ascii //weight: 1
        $x_1_4 = "/GPJar0L" ascii //weight: 1
        $x_1_5 = "Lcom/d/m/gp/a/i;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

