rule HackTool_Win64_Tedy_LR_2147978727_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Tedy.LR!MTB"
        threat_id = "2147978727"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Tedy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] inject code:" ascii //weight: 1
        $x_2_2 = "[+] BlackBone mapped DLL at 0x%llX" ascii //weight: 2
        $x_3_3 = "[-] inject: %ws" ascii //weight: 3
        $x_4_4 = "[*] Killing Steam process..." ascii //weight: 4
        $x_5_5 = "taskkill /F /IM steam.exe >nul 2>" ascii //weight: 5
        $x_6_6 = "[-] inject from memory: OpenProcess failed" ascii //weight: 6
        $x_7_7 = "[+] BlackBone mapped memory DLL at 0x%llX" ascii //weight: 7
        $x_8_8 = "[-] inject from memory: status 0x%X" ascii //weight: 8
        $x_9_9 = "Evosense\\injector_log.txt" ascii //weight: 9
        $x_10_10 = "Successfully Injected" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

