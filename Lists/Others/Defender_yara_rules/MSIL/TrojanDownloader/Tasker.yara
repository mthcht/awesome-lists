rule TrojanDownloader_MSIL_Tasker_G_2147741104_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Tasker.G!MTB"
        threat_id = "2147741104"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tasker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uejvcumu\"1etgcvg\"1ue\"okpwvg\"1oq\"3\"1vp" wide //weight: 1
        $x_1_2 = "Kpxqmg/Gzrtguukqp" wide //weight: 1
        $x_1_3 = "RANDOM" wide //weight: 1
        $x_1_4 = "jvvru<11" wide //weight: 1
        $x_1_5 = "rcuvg0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

