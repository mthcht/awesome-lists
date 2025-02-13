rule TrojanDownloader_MSIL_PurelogStealer_RFAK_2147925940_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PurelogStealer.RFAK!MTB"
        threat_id = "2147925940"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PurelogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ti8To1jtgtPb08hYJtKz7g==" ascii //weight: 1
        $x_1_2 = "mWcsytLYjf8=" ascii //weight: 1
        $x_1_3 = "http://46.8.237.66/spool02/Odgcgoez.wav" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

