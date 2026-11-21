rule Trojan_Win64_Pycoon_AY_2147982560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pycoon.AY!MTB"
        threat_id = "2147982560"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pycoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "BOTCFG|" ascii //weight: 4
        $x_3_2 = "Local\\BotC2Stub.SingleInstance" ascii //weight: 3
        $x_2_3 = "BOTCFG|host=axwtexa.ddns.net|fallback=back001xtc.ddns.net|port=8080|tag=DGM|name=Runtimebroker|persist=reg|" ascii //weight: 2
        $x_1_4 = "PERSISTENCE_INSTALL" ascii //weight: 1
        $x_1_5 = "PERSISTENCE_REMOVE" ascii //weight: 1
        $x_1_6 = "schtasks.exe /delete /f /tn" ascii //weight: 1
        $x_1_7 = "wrapped/injected, persistence skipped, staying resident" ascii //weight: 1
        $x_1_8 = "CLIPPER_CONFIG" ascii //weight: 1
        $x_1_9 = "SCREENCAST_START" ascii //weight: 1
        $x_1_10 = "SCREENCAST_STOP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

