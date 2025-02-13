rule Trojan_Win32_Adkuadu_A_2147697726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adkuadu.A"
        threat_id = "2147697726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adkuadu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://www.hao123.com/?tn=29065018_138_hao_pg" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\BaiduBrowser" wide //weight: 1
        $x_1_3 = "http://dl.client.baidu.com/union/getbdbrowser.php?tn=39005028_224" wide //weight: 1
        $x_1_4 = "http://d1.kuai8.com/setup/kuai8_rar.exe" wide //weight: 1
        $x_1_5 = {50 4f 50 55 50 [0-16] 41 43 54 49 56 45}  //weight: 1, accuracy: Low
        $x_1_6 = "IEFrame" wide //weight: 1
        $x_1_7 = "shell32.dll,OpenAs_RunDLL" wide //weight: 1
        $x_1_8 = "{8856F961-340A-11D0-A96B-00C04FD705A2}" wide //weight: 1
        $x_1_9 = "{D27CDB6E-AE6D-11CF-96B8-444553540000}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

