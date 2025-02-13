rule Trojan_MSIL_VanillaRat_CXJK_2147849512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VanillaRat.CXJK!MTB"
        threat_id = "2147849512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VanillaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Debug\\VanillaRat.pdb" ascii //weight: 1
        $x_1_2 = "Remote Shell" wide //weight: 1
        $x_1_3 = "Password Viewer" wide //weight: 1
        $x_1_4 = "Audio Recorder" wide //weight: 1
        $x_1_5 = "Keylogger" wide //weight: 1
        $x_1_6 = "Remote Desktop Viewer" wide //weight: 1
        $x_1_7 = "btnRestartShell" wide //weight: 1
        $x_1_8 = "VanillaRat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

