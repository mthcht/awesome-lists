rule Trojan_Win64_DLLSideLoader_DN_2147980419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLSideLoader.DN!MTB"
        threat_id = "2147980419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLSideLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command" ascii //weight: 1
        $x_1_2 = "loaderca.log" ascii //weight: 1
        $x_1_3 = "XYhtt30X5NF5xMMrSXSuzS81o0BdTz9DVB5GJcI7" ascii //weight: 1
        $x_1_4 = "[Reflection.Assembly]::Load" ascii //weight: 1
        $x_1_5 = "ShowWindowAsync((Get-Process" ascii //weight: 1
        $x_2_6 = {48 8d bc 24 30 02 00 00 41 31 c1 ff d6 48 8b 4c 24 58 49 89 d9 ba}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

