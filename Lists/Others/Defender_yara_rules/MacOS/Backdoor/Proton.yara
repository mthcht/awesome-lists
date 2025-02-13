rule Backdoor_MacOS_Proton_A_2147750222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Proton.A!MTB"
        threat_id = "2147750222"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Proton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.dio3we/.prelim.png" ascii //weight: 1
        $x_1_2 = "Symantec Malware Detector/FMDatabaseQueue.m" ascii //weight: 1
        $x_1_3 = "com.Symantec.smd" ascii //weight: 1
        $x_1_4 = "symantecheurengine.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Proton_C_2147752179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Proton.C!MTB"
        threat_id = "2147752179"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Proton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unzip -d /tmp %@/.pl.zip" ascii //weight: 1
        $x_1_2 = "open /tmp/Updater.app" ascii //weight: 1
        $x_1_3 = "com.Eltima.UpdaterAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_Proton_E_2147793067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Proton.E!MTB"
        threat_id = "2147793067"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Proton"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 6e 7a 69 70 20 2d 6f 20 2f 74 6d 70 2f 25 40 20 26 26 20 6f 70 65 6e 20 2f 74 6d 70 2f 25 40 2e 61 70 70 [0-4] 63 68 6d 6f 64 20 2b 78 20 2f 74 6d 70 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {70 79 74 68 6f 6e 20 25 40 2f [0-4] 2e 70 79}  //weight: 1, accuracy: Low
        $x_1_3 = "/Library/Application Support/Google/Chrome/%@/Login Data" ascii //weight: 1
        $x_1_4 = "/Library/Application Support/Bitcoin/wallet.dat" ascii //weight: 1
        $x_1_5 = "remote_execute" ascii //weight: 1
        $x_1_6 = "force_update" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

