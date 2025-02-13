rule Trojan_MSIL_Qrob_RPQ_2147823124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Qrob.RPQ!MTB"
        threat_id = "2147823124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Qrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-112] 43 00 72 00 79 00 70 00 74 00 6f 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = "CockyGrabber.Grabbers.ChromeGrabber" wide //weight: 1
        $x_1_3 = "GetLogins" wide //weight: 1
        $x_1_4 = "ActionUrl" wide //weight: 1
        $x_1_5 = "freegeoip.app" wide //weight: 1
        $x_1_6 = "fudloader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

