rule Trojan_Win32_Garvi_PAA_2147781311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garvi.PAA!MTB"
        threat_id = "2147781311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garvi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta \"javascript:function getT(a){var b,c=new ActiveXObject('WinHttp.WinHttpRequest.5.1');return c.Open('GET',a,!1),c.Send(),b=c.ResponseText,b}" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {6d 61 72 69 75 73 2f 6c 6f 61 64 65 72 2f 6c 2e 70 68 70 3f [0-10] 27 29 29 3b 22}  //weight: 1, accuracy: Low
        $x_1_4 = "RegSetValueExA" ascii //weight: 1
        $x_1_5 = "RegCreateKeyA" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "GetCurrentProcess" ascii //weight: 1
        $x_1_8 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Garvi_DF_2147822004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Garvi.DF!MTB"
        threat_id = "2147822004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Garvi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 03 8a 84 05 [0-4] 30 04 11 41 3b 8d e8 fd ff ff 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 18 0f b6 14 07 0f be cb 3b ca 75 5f 84 db 74 07 46 40 83 fe 08 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

