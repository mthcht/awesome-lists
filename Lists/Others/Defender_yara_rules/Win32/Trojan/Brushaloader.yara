rule Trojan_Win32_Brushaloader_S_2147745233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brushaloader.S!MSR"
        threat_id = "2147745233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brushaloader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nose\\Base\\listen\\thick\\Company\\river\\Wave\\Sandbe.pdb" ascii //weight: 1
        $x_1_2 = "DecodeObject" ascii //weight: 1
        $x_1_3 = "FindCertificateInStore" ascii //weight: 1
        $x_1_4 = "GetUserObjectInformation" ascii //weight: 1
        $x_1_5 = "GetLastActivePopup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

