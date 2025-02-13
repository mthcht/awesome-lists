rule Trojan_Win32_AutoInj_PRB_2147755935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInj.PRB!MTB"
        threat_id = "2147755935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://installs.cpa-install.com/ClientFiles/get/" ascii //weight: 1
        $x_1_2 = "FILEEXTENSION = \".tmp\"" ascii //weight: 1
        $x_1_3 = "REGWRITE ( $ONE1RK" ascii //weight: 1
        $x_1_4 = "SHELLEXECUTE ( $SFILEPATH" ascii //weight: 1
        $x_1_5 = "REGREAD ( \"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\" , \"SM_Games_pl\" )" ascii //weight: 1
        $x_1_6 = "RUN ( $EXFILEPATHP & \" /q \" , \"\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AutoInj_GZN_2147916388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoInj.GZN!MTB"
        threat_id = "2147916388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 19 a8 bf 9d 8c 5b 6c ed f0 34 30 bb b0 63 98 6c ?? ?? 6b 18 95 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

