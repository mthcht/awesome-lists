rule Trojan_Win64_FsoRAT_YBG_2147950100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FsoRAT.YBG!MTB"
        threat_id = "2147950100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FsoRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SvcUpdate_" ascii //weight: 10
        $x_10_2 = "WindowsUpdateService_" ascii //weight: 10
        $x_10_3 = "svchost_" ascii //weight: 10
        $x_10_4 = "schtasks /create" ascii //weight: 10
        $x_10_5 = "%s/bot%s/sendDocument" ascii //weight: 10
        $x_10_6 = "/saludo" ascii //weight: 10
        $x_10_7 = "/screenshot" ascii //weight: 10
        $x_10_8 = "/keylog <start|stop|dump>" ascii //weight: 10
        $x_10_9 = "/exfil_get <nombre_archivo> <ruta>" ascii //weight: 10
        $x_10_10 = "/clipboard" ascii //weight: 10
        $x_10_11 = "/list_victims" ascii //weight: 10
        $x_1_12 = {80 74 24 62 ?? 45 33 c0 80 74 24 63 ?? 80 74 24 64 ?? 80 74 24 65 ?? 80 74 24 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

