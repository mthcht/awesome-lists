rule Trojan_Win32_Mofksys_EM_2147851996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mofksys.EM!MTB"
        threat_id = "2147851996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c1 e9 02 31 02 83 c2 04 49 0f 85 f4 ff ff ff 5d c2 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mofksys_A_2147918569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mofksys.A!MTB"
        threat_id = "2147918569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project1.uExWatch" ascii //weight: 1
        $x_1_2 = "lIEObject_DocumentComplete" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mofksys_B_2147918570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mofksys.B!MTB"
        threat_id = "2147918570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mofksys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A*\\AF:\\RFD\\xNewCode\\xNewPro\\xT\\trjFN\\Project1.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

