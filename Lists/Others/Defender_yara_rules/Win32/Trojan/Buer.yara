rule Trojan_Win32_Buer_PA_2147755565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buer.PA!MTB"
        threat_id = "2147755565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shellcode" ascii //weight: 1
        $x_1_2 = "uacbypass" ascii //weight: 1
        $x_1_3 = "localscript" ascii //weight: 1
        $x_1_4 = "powershell.exe \"-Command\" \"if((Get-ExecutionPolicy ) -ne  'AllSigned')  { Set-ExecutionPolicy -Scope Process Bypass }; & '" wide //weight: 1
        $x_1_5 = {0f b6 c1 03 c6 0f b6 f0 8a 84 35 ?? ?? ?? ff 88 84 3d ?? ?? ?? ff 8b 45 fc 88 8c 35 ?? ?? ?? ff 0f b6 94 3d ?? ?? ?? ff 0f b6 c9 03 d1 0f b6 ca 8a 8c 0d ?? ?? ?? ff 30 08 40 89 45 fc 83 eb 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

