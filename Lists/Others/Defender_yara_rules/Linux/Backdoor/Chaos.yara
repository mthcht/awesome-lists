rule Backdoor_Linux_Chaos_A_2147852693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Chaos.A!MTB"
        threat_id = "2147852693"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "victimSize" ascii //weight: 1
        $x_1_2 = "UserAgent" ascii //weight: 1
        $x_1_3 = "sessionId" ascii //weight: 1
        $x_1_4 = "url.Userinfo" ascii //weight: 1
        $x_1_5 = "http.fakeLocker" ascii //weight: 1
        $x_1_6 = "ForceAttemptHTTP2" ascii //weight: 1
        $x_1_7 = "main.ServerAddress=" ascii //weight: 1
        $x_1_8 = "tiagorlampert/CHAOS/client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

