rule TrojanDropper_MacOS_X_Ventir_A_2147689599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MacOS_X/Ventir.A"
        threat_id = "2147689599"
        type = "TrojanDropper"
        platform = "MacOS_X: "
        family = "Ventir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<string>com.updated.launchagent</string>" ascii //weight: 1
        $x_1_2 = "load %s/com.updated.launchagent.plist" ascii //weight: 1
        $x_1_3 = "tar -xf %s/kext.tar" ascii //weight: 1
        $x_1_4 = "/bin/chmod -R 755 /System/Library/Extensions/updated.kext" ascii //weight: 1
        $x_1_5 = {2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 [0-16] 5b 25 73 5d [0-16] 25 73 2f 75 70 64 61 74 65 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

