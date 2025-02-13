rule Trojan_Win32_Hesv_AF_2147838633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hesv.AF!MTB"
        threat_id = "2147838633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This is last warning,the malware author couldn't assume legal liability,so are you sure to run it?" ascii //weight: 1
        $x_1_2 = "This Malware will disturb you for some time,are you sure to run it?" ascii //weight: 1
        $x_1_3 = "You are a Idiot" ascii //weight: 1
        $x_1_4 = "Fuck You" ascii //weight: 1
        $x_1_5 = "GDI Malware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hesv_HNC_2147907919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hesv.HNC!MTB"
        threat_id = "2147907919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 7b b1 42 6c 32 7c 34 41 85 44 f3 34 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hesv_NIT_2147925280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hesv.NIT!MTB"
        threat_id = "2147925280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "start.bat" ascii //weight: 2
        $x_2_2 = "__tmp_rar_sfx_access_check_%u" ascii //weight: 2
        $x_2_3 = "unknowndll.pdb" ascii //weight: 2
        $x_1_4 = "KJO_UPDATE\\kjo_update.bat" ascii //weight: 1
        $x_1_5 = "KJO_UPDATE\\wget.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

