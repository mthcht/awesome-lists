rule Trojan_MSIL_BTMobRat_AB_2147966313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BTMobRat.AB!MTB"
        threat_id = "2147966313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BTMobRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_coin_monero1" ascii //weight: 1
        $x_1_2 = "BTMOB.CameraMonitor.resources" ascii //weight: 1
        $x_1_3 = "Offline keylogger" ascii //weight: 1
        $x_1_4 = "BTMOB.LiveKeylogger.resources" ascii //weight: 1
        $x_1_5 = "BTMob.exe" ascii //weight: 1
        $x_1_6 = "miner" ascii //weight: 1
        $x_1_7 = "payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BTMobRat_AC_2147969378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BTMobRat.AC!MTB"
        threat_id = "2147969378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BTMobRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_coin_monero" ascii //weight: 1
        $x_1_2 = "BTMOB.CameraMonitor.resources" ascii //weight: 1
        $x_1_3 = "Offline keylogger" ascii //weight: 1
        $x_1_4 = "BTMOB.LiveKeylogger.resources" ascii //weight: 1
        $x_1_5 = "Capture the lock screen (pin/pattern/password) to use it later with live screen tool." ascii //weight: 1
        $x_1_6 = "BTMOB injection" ascii //weight: 1
        $x_1_7 = "payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

