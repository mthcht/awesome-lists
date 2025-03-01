rule HackTool_Win32_KeyGen_VI_2147744901_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeyGen.VI!MTB"
        threat_id = "2147744901"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyGen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKLM\\SYSTEM\\Tokens\\Kernel, Kernel-ProductInfo, %NewSku%" ascii //weight: 1
        $x_1_2 = "HKLM\\SYSTEM\\Tokens\\Kernel, Security-SPP-GenuineLocalStatus" ascii //weight: 1
        $x_1_3 = "%dir%\\gatherosstate.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_KeyGen_A_2147832750_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeyGen.A!MTB"
        threat_id = "2147832750"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyGen"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 8a 56 01 8a 5e 02 8a e0 8a f2 8a fb 80 e4 03 80 e6 0f 80 e7 3f c0 e8 02 c0 ea 04 c0 eb 06 c0 e4 04 c0 e6 02 0a e2 0a de 0f b6 d0 0f b6 cc}  //weight: 1, accuracy: High
        $x_1_2 = "-pubkey" ascii //weight: 1
        $x_1_3 = "-privkey" ascii //weight: 1
        $x_1_4 = "DECRYPTION_ID.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

