rule Trojan_Win64_Pantera_ARA_2147976392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pantera.ARA!MTB"
        threat_id = "2147976392"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pantera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "noexport.dll" wide //weight: 10
        $x_10_2 = "noexport.pdb" ascii //weight: 10
        $x_10_3 = "ExtractAndSendPasswords" ascii //weight: 10
        $x_5_4 = "KeyloggerStart" ascii //weight: 5
        $x_5_5 = "ClipboardMonitorStart" ascii //weight: 5
        $x_1_6 = "HttpWebRequest" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

