rule Trojan_Win32_Clicker_GPA_2147904539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clicker.GPA!MTB"
        threat_id = "2147904539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 8d 44 24 14 89 54 24 04 8d 4c 24 04 89 54 24 08 50 89 54 24 10 51 89 54 24 18 66 c7 44 24 0c 34 08}  //weight: 5, accuracy: High
        $x_1_2 = "Malservice" ascii //weight: 1
        $x_1_3 = "HGL345" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clicker_RP_2147904790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clicker.RP!MTB"
        threat_id = "2147904790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ok.exe" ascii //weight: 1
        $x_1_2 = "D:\\Projects\\New\\App\\App\\bin\\Release\\new\\ok.pdb" ascii //weight: 1
        $x_1_3 = "playnew();" wide //weight: 1
        $x_1_4 = "tgbnhy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Clicker_PADL_2147913609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Clicker.PADL!MTB"
        threat_id = "2147913609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Clicker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "clickinfo.dll?getkeyword" ascii //weight: 1
        $x_1_2 = "ReferClick.click()" ascii //weight: 1
        $x_1_3 = "SetBaiduSearchKeyWord" ascii //weight: 1
        $x_1_4 = "BaiduClick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

