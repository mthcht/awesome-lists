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

rule HackTool_Win32_KeyGen_AMTB_2147931343_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeyGen!AMTB"
        threat_id = "2147931343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Keygenned by" ascii //weight: 2
        $x_2_2 = "FFFKEYGEN" ascii //weight: 2
        $x_1_3 = "FiGHTiNG FOR FUN PRESENTS" ascii //weight: 1
        $x_1_4 = "SeVeN / FFF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule HackTool_Win32_KeyGen_AMTB_2147931343_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeyGen!AMTB"
        threat_id = "2147931343"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyGen"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 6e 2d 67 65 6e 23 30 31 [0-15] 46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 61 63 6b 65 72 20 3a 20 4e 2d 47 65 6e [0-4] 50 72 6f 74 65 63 74 69 6f 6e 20 3a 20 43 72 61 70 70 79 20 56 42 20 21 21 21 [0-4] 54 68 6b 73 20 3a 20 4e 2d 47 65 6e 20 63 72 65 77 20 3b 29 [0-4] 4d 41 59 20 54 48 45 20 4c 55 4d 49 4e 4f 55 20 42 45 20 57 49 54 48 20 59 4f 55 20 21 21 [0-150] 45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {56 65 72 73 69 6f 6e 20 4d 6f 6e 6f 70 6f 73 74 65 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73 [0-5] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-10] 50 6f 73 74 65 73}  //weight: 1, accuracy: Low
        $x_1_4 = "-------www.cerror.tk--" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

